package com.gutschke.wgrtc.signalling

import kotlinx.coroutines.delay
import kotlinx.coroutines.withTimeoutOrNull

/**
 * Receiver-side handshake race — Step F.1 of the candidate-negotiation
 * v2 design.
 *
 * Pure-JVM orchestration of:
 * 1. picker — same-subnet override + strict-mode policy
 * ([pickReceiverCandidates]).
 * 2. probe — UDP reachability filter ([probeAllCandidates]).
 * 3. race — for each surviving candidate in priority order, ask
 * the [TunnelEndpointController] to set it as the active
 * endpoint and wait up to `perCandidateTimeoutMs` for a WG
 * handshake to complete. Advance on timeout.
 *
 * The Android-specific bits (`GoBackend.setState`, `Statistics`,
 * `ConnectivityManager.bindSocket`) live behind
 * [TunnelEndpointController] so this orchestration can be exhaustively
 * unit-tested without an emulator. Step F.2 provides the production
 * implementation; Step F.3 wires `WgrtcViewModel.connect` to use the
 * runner.
 */

/** Abstraction over the backend operations the race needs. Production
 * impl wraps `WgrtcApp.instance.backend` + the tunnel store; tests use
 * a scripted fake. */
interface TunnelEndpointController {
    /**
     * Switch the active endpoint to [candidate] for tunnel [tunnelId],
     * binding outgoing traffic to [egressInterface] (Android `Network`)
     * if non-null. Implementations rewrite the persisted config's
     * `Endpoint = ` line and call `setState(DOWN)→setState(UP, …)` —
     * see project_wg_tunnel_jni_api_surface.md for why DOWN+UP is the
     * only available mechanism (no `wgSetConfig` JNI).
     *
     * Throws if the backend rejects the new config. The runner
     * surfaces the failure reason to the caller.
     */
    suspend fun setEndpoint(
        tunnelId: String,
        candidate: EndpointUpdate,
        egressInterface: String?,
    )

    /** Latest WG handshake completion time as epoch milliseconds, or
     * 0 if no handshake has completed since the active tunnel came
     * up. Polled by the race loop. */
    suspend fun latestHandshakeMs(): Long

    /** Tear down the active tunnel. Called by the runner on hard
     * failure (all candidates exhausted) or by the caller on
     * user-driven Disconnect. */
    suspend fun bringDown()
}

sealed class ConnectAttemptResult {
    data class Success(
        val finalEndpoint: EndpointUpdate,
        val egressInterface: String?,
        val handshakeWaitMs: Long,
    ) : ConnectAttemptResult()

    data class Failed(
        val reason: String,
        val triedCandidates: List<EndpointUpdate>,
        /** True if the runner stopped early because strict-hotspot mode
         * exhausted same-subnet candidates and refused to fall back to
         * the public-rank candidates. UI surfaces this differently
         * ("local connection failed; not falling back to cellular")
         * vs a generic exhaustion failure. */
        val strictModeBlocked: Boolean = false,
    ) : ConnectAttemptResult()
}

class ConnectionRunner(
    private val controller: TunnelEndpointController,
    private val probe: UdpProbe = RealUdpProbe(),
    private val nowMs: () -> Long = { System.currentTimeMillis() },
    /** How long to wait at the start of [connect] for the
     * caller's pre-race device bring-up to complete a handshake
     * against the persisted Endpoint before we disturb the
     * working session. 0L disables the shortcut (used by unit
     * tests that drive setEndpoint exclusively); production uses
     * the default. */
    private val preRaceHandshakeWindowMs: Long = 2_500L,
) {

    /**
     * Single connection attempt: pick → probe → race.
     *
     * @param tunnelId the tunnel to bring up.
     * @param candidates sender-supplied candidate list (in
     * sender-rank order; same-subnet
     * override re-ranks internally).
     * @param localInterfaces receiver's local interfaces (typically
     * `enumerateLocalInterfaces()`); empty list
     * disables same-subnet detection.
     * @param strictHotspot if true and at least one candidate is
     * same-subnet, the runner WILL NOT fall
     * back to non-same-subnet candidates.
     * THE hotspot data-leak guarantee.
     * @param perCandidateTimeoutMs how long to wait for a WG
     * handshake before advancing to the next
     * candidate. Must be GREATER than WG's
     * 5 s retry interval — at 5 s the runner
     * tears down at the exact moment the
     * kernel fires its first retry, never
     * giving the retry a chance to complete.
     * 12 s leaves room for one full retry
     * cycle to land, which is what saves us
     * when the first packet is delayed (Wi-Fi
     * power-save wake-up: pings show 1+ s for
     * the first packet, milliseconds after).
     * @param probeBudgetMs wall-clock budget for the parallel UDP
     * probe sweep ahead of the race.
     */
    suspend fun connect(
        tunnelId: String,
        candidates: List<EndpointUpdate>,
        localInterfaces: List<LocalInterface>,
        strictHotspot: Boolean = true,
        perCandidateTimeoutMs: Long = 12_000L,
        probeBudgetMs: Long = 1_500L,
    ): ConnectAttemptResult {
        if (candidates.isEmpty()) {
            return ConnectAttemptResult.Failed(
                reason = "no candidates supplied",
                triedCandidates = emptyList(),
            )
        }

        // 1. Picker: same-subnet override + strict-mode filter.
        val picked = pickReceiverCandidates(
            candidates, localInterfaces, strictHotspot,
        )

        // 1a. Pre-race shortcut. The caller (WgrtcViewModel.connect)
        // has already brought wireguard-go UP with the persisted
        // Endpoint baked in. If that Endpoint is still reachable
        // the handshake will complete within a few hundred
        // milliseconds — long before we touch the working session
        // with setEndpoint. Skipping the race here keeps the
        // persisted endpoint live (cheap path).
        //
        // Skip the shortcut when running the full race would
        // yield a meaningfully better endpoint (a same-subnet
        // candidate sits at the top of `picked`, but the
        // persisted endpoint is almost certainly the daemon's
        // public IP —) OR when the controller already
        // has a (stale) recorded handshake from a prior session.
        // The "prior session" case matters for roams:
        // [RoamController] calls connect() again on the same
        // controller after a network change, by which time
        // `latestHandshakeMs` is still the OLD endpoint's value.
        // Comparing waitForHandshake against that baseline
        // ensures we only short-circuit on a NEW handshake.
        val firstPickedIsSameSubnet =
            picked.firstOrNull()?.isSameSubnet == true
        if (!firstPickedIsSameSubnet) {
            val handshakeMsBeforePreRace = controller.latestHandshakeMs()
            val preWaited = waitForHandshake(
                handshakeMsBeforePreRace, preRaceHandshakeWindowMs)
            if (preWaited != null) {
                // We don't know which candidate index the persisted
                // Endpoint matches; first candidate is fine for the
                // informational ConnectAttemptResult, and
                // egressInterface=null skips the persist-rewrite path
                // because the persisted Endpoint already matches what's
                // live.
                return ConnectAttemptResult.Success(
                    finalEndpoint = candidates.first(),
                    egressInterface = null,
                    handshakeWaitMs = preWaited,
                )
            }
        }
        if (picked.isEmpty()) {
            // Defensive — pickReceiverCandidates returns the input
            // if no override applies, so empty here means strict
            // mode dropped EVERY candidate. Should be unreachable
            // (strict mode only filters when same-subnet matches
            // exist, which means at least one survives) but be safe.
            controller.bringDown()
            return ConnectAttemptResult.Failed(
                reason = "picker returned empty (strict mode? no usable candidate?)",
                triedCandidates = candidates,
                strictModeBlocked = strictHotspot,
            )
        }

        // 2. Probe: UDP reachability filter. Eliminate definitively-
        // Unreachable candidates; keep Reachable + Silent for the
        // race (silence is plausible — many firewalls drop probes
        // silently on legitimate paths).
        val outcomes = probeAllCandidates(
            probe, picked.map { it.candidate },
            totalBudgetMs = probeBudgetMs,
        )
        val survivors = picked.zip(outcomes)
            .filter { (_, o) -> o.result != ProbeResult.Unreachable }
            .map { it.first }
        if (survivors.isEmpty()) {
            // All candidates returned ENETUNREACH/EHOSTUNREACH —
            // network layer can't even route to any of them. Bail
            // before spending 5 s/candidate on doomed handshakes.
            controller.bringDown()
            return ConnectAttemptResult.Failed(
                reason = "every candidate was confirmed unreachable",
                triedCandidates = picked.map { it.candidate },
                strictModeBlocked = strictHotspot &&
                    picked.all { it.isSameSubnet },
            )
        }

        // 3. Race: try each survivor until a WG handshake completes.
        val tried = mutableListOf<EndpointUpdate>()
        for (s in survivors) {
            tried += s.candidate
            val handshakeMsBefore = controller.latestHandshakeMs()
            try {
                controller.setEndpoint(tunnelId, s.candidate, s.egressInterface)
            } catch (e: kotlinx.coroutines.CancellationException) {
                // Cooperative cancellation (disconnect or G-cancel
                // restart) — propagate immediately, do NOT advance to
                // the next candidate. Bug pre-2026-05-08: catch
                // (Exception) above swallowed CancellationException,
                // making cancel-and-join silently advance through
                // every remaining candidate.
                throw e
            } catch (e: Exception) {
                // Backend rejected the config — try next candidate.
                // Logging is the production controller's job; here we
                // just continue the race.
                continue
            }
            val waited = waitForHandshake(handshakeMsBefore, perCandidateTimeoutMs)
            if (waited != null) {
                return ConnectAttemptResult.Success(
                    finalEndpoint = s.candidate,
                    egressInterface = s.egressInterface,
                    handshakeWaitMs = waited,
                )
            }
            // No handshake within timeout — advance to next candidate.
            // We DON'T tear down here; setEndpoint of the next
            // candidate will replace the active state.
        }

        // 4. All survivors exhausted. Strict-mode result depends on
        // whether ALL survivors were same-subnet (indicating we're
        // on the hotspot LAN and the host is unreachable) or mixed
        // (we tried public too, so it's a generic failure).
        // The last setEndpoint left the backend UP on a non-
        // handshaking endpoint — bring it down so the caller's
        // "Failed" result corresponds to a clean DOWN state, not
        // a zombie tunnel UP that wastes battery and confuses the
        // UI's _activeTunnelId / _liveState pair. of the
        // candidate-negotiation v2 review.
        controller.bringDown()
        val allSameSubnet = picked.all { it.isSameSubnet }
        return ConnectAttemptResult.Failed(
            reason = "no handshake completed after ${survivors.size} candidates",
            triedCandidates = tried,
            strictModeBlocked = strictHotspot && allSameSubnet,
        )
    }

    /** Poll [TunnelEndpointController.latestHandshakeMs] until it
     * advances past [previous] or [budgetMs] elapses. Returns the
     * wall-clock wait time on success, null on timeout. */
    private suspend fun waitForHandshake(previous: Long, budgetMs: Long): Long? {
        val deadline = nowMs() + budgetMs
        val start = nowMs()
        // Poll cadence: 100ms first second, then 250ms. Captures
        // sub-second handshakes accurately without burning CPU on
        // the long tail.
        var pollMs = 100L
        while (nowMs() < deadline) {
            delay(pollMs)
            val current = controller.latestHandshakeMs()
            if (current > previous) return nowMs() - start
            if (nowMs() - start > 1_000L) pollMs = 250L
        }
        return null
    }
}
