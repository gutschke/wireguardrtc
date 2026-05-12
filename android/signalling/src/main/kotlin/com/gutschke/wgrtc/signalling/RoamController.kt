package com.gutschke.wgrtc.signalling

import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/** Diagnostic logger surface for RoamController. Real impl in the
 * signalling module would pull in android.util.Log which the
 * pure-Kotlin module doesn't (and shouldn't) depend on. The ViewModel
 * hands one of these in at construction. Default = no-op for tests. */
fun interface RoamLogger {
    fun log(level: Char, message: String)
    companion object { val NONE: RoamLogger = RoamLogger { _, _ -> } }
}

/**
 * Client-side roam handler. Built on top of an already-running
 * [TunnelEndpointController] + [ConnectionRunner] (created by the
 * initial connect race); the [WgrtcViewModel] hands those references
 * over after a successful connect and the roam controller takes over
 * for the rest of the tunnel's life.
 *
 * # Why this exists
 *
 * When the phone roams between underlying networks — e.g. from
 * home WiFi (where `10.0.0.x` was the picked LAN candidate) to
 * cellular (where `10.0.0.x` is not routable) — wireguard-go's
 * outbound handshake retries go to dead air. The
 * [NetworkChangeMonitor] already fires `hub.wake(force=true)` on
 * the relevant Android events, which causes the daemon to send a
 * fresh OFFER with the current candidate list. That refreshes the
 * listener's candidate cache, but **does not** push a new endpoint
 * into the running wireguard-go device. The result is the user's
 * tunnel sits with "data going out, none coming back" until they
 * manually disconnect/reconnect.
 *
 * [RoamController] closes that loop by:
 *
 * 1. Hooking the same [NetworkChangeMonitor] callback.
 * 2. Debouncing rapid bursts (one re-race per settled change).
 * 3. After the settle delay, reading
 * [TunnelEndpointController.latestHandshakeMs] — if the
 * handshake is recent (< [staleHandshakeMs] old) the data path
 * is still healthy and no roam is needed.
 * 4. Otherwise re-enumerating local interfaces, pulling fresh
 * candidates, and running [ConnectionRunner.connect] against
 * the **existing** controller. No JoinerVpnService rebind, no
 * full disconnect+connect cycle — just in-place
 * `setEndpoint` calls into wireguard-go's UAPI.
 *
 * The class is pure-Kotlin, hand-driven by a CoroutineScope handed
 * in at construction. All Android specifics live one layer up in
 * the [WgrtcViewModel] integration.
 *
 * # Lifecycle
 *
 * - Constructed (and reachable from outside) by the ViewModel
 * after a successful connect race.
 * - [onNetworkChanged] is called from the existing
 * [NetworkChangeMonitor] callback — multiple times, freely.
 * - [stop] is called by the ViewModel on user-initiated
 * disconnect (or tunnel teardown). After [stop] this instance
 * becomes inert; all pending checks are cancelled and further
 * [onNetworkChanged] calls are ignored.
 */
class RoamController(
    private val tunnelId: String,
    private val controller: TunnelEndpointController,
    private val runner: ConnectionRunner,
    private val candidateProvider: suspend () -> List<EndpointUpdate>,
    private val ifaceProvider: suspend () -> List<LocalInterface>,
    private val scope: CoroutineScope,
    /** Time to wait between an [onNetworkChanged] firing and the
     * staleness check. Gives the wake-driven OFFER a chance to
     * land + wireguard-go's keepalive retries time to recover the
     * connection on its own (which happens fairly often when the
     * same network briefly hiccups but the path is still good). */
    private val settleDelayMs: Long = 8_000L,
    /** Handshake "freshness" threshold. If the controller's
     * latestHandshakeMs is younger than this when the settle check
     * fires, the tunnel is considered healthy and no re-race is
     * needed. Tuned to be longer than wg-go's persistent-
     * keepalive interval (25 s) by a margin so a healthy idle
     * tunnel isn't falsely flagged. */
    private val staleHandshakeMs: Long = 30_000L,
    private val nowMs: () -> Long = { System.currentTimeMillis() },
    private val onResult: ((ConnectAttemptResult) -> Unit)? = null,
    /** strictHotspot policy to forward to [ConnectionRunner.connect]
     * on the re-race. Default false — same as the joiner's
     * initial connect; the user explicitly asked for "prefer LAN,
     * fall back to public" rather than "LAN only". */
    private val strictHotspot: Boolean = false,
    /** Forwarded to [ConnectionRunner.connect] on the re-race.
     * Exposed so tests can drive a fast-fail. */
    private val perCandidateTimeoutMs: Long = 12_000L,
    private val probeBudgetMs: Long = 1_500L,
    private val logger: RoamLogger = RoamLogger.NONE,
    /** Defense-in-depth: every [pollIntervalMs] re-run the staleness
     * check without waiting for any Android event. Covers the case
     * where the OS fails to deliver onLost/onAvailable for a VPN
     * underlying-transport switch (observed on Android phone: WiFi disabled
     * → cellular took over silently, no callback for 57 s). Disabled
     * by passing 0L. */
    private val pollIntervalMs: Long = 20_000L,
    /** Dispatcher for the pending and polling jobs. Defaults to
     * [Dispatchers.Default] — NOT Main — because empirical evidence
     * on Android phone shows Main-dispatched `delay()` jobs occasionally
     * fail to wake (foreground activity, Main idle, body never
     * resumed). Default's thread-pool timer is reliable. */
    private val dispatcher: CoroutineDispatcher = Dispatchers.Default,
) {
    private val mutex = Mutex()
    @Volatile private var pendingJob: Job? = null
    @Volatile private var pollJob: Job? = null
    @Volatile private var stopped = false

    /**
     * Signal that an Android-level network change happened. May be
     * called many times. Each call cancels any in-flight pending
     * check and replaces it with a fresh one delayed by
     * [settleDelayMs] — so a burst of changes (which Android often
     * delivers as a sequence of onLost/onAvailable/onLPC events)
     * coalesces into a single re-race attempt.
     */
    fun onNetworkChanged() {
        if (stopped) {
            logger.log('D', "onNetworkChanged ignored — stopped")
            return
        }
        val hadPending = pendingJob != null
        pendingJob?.cancel()
        logger.log(
            'I',
            "onNetworkChanged: scheduling staleness check in ${settleDelayMs}ms" +
                if (hadPending) " (cancelled previous pending)" else "",
        )
        pendingJob = scope.launch(dispatcher) {
            logger.log('D', "staleness check job started; sleeping ${settleDelayMs}ms")
            delay(settleDelayMs)
            runStalenessCheck("event")
        }
    }

    /** Kick the polling loop. Called once from the ViewModel after
     * construction. Idempotent. */
    fun startPolling() {
        if (stopped || pollIntervalMs <= 0L) return
        if (pollJob?.isActive == true) return
        logger.log('I', "starting polling loop (interval=${pollIntervalMs}ms)")
        pollJob = scope.launch(dispatcher) {
            while (isActive && !stopped) {
                delay(pollIntervalMs)
                if (stopped) break
                runStalenessCheck("poll")
            }
        }
    }

    /** Shared staleness check used by both onNetworkChanged() and the
     * polling loop. `trigger` is just for log readability. */
    private suspend fun runStalenessCheck(trigger: String) {
        // Serialize so a poll-driven check can't race against an
        // event-driven check (and so two near-simultaneous events
        // don't both reach the connect() call at the same time).
        mutex.withLock {
            if (stopped) return
            val handshakeMs = controller.latestHandshakeMs()
            val handshakeAge = if (handshakeMs <= 0L) Long.MAX_VALUE
                               else nowMs() - handshakeMs
            if (handshakeAge < staleHandshakeMs) {
                logger.log(
                    'D',
                    "$trigger: handshake age ${handshakeAge}ms < " +
                        "${staleHandshakeMs}ms → healthy",
                )
                return
            }
            logger.log(
                'I',
                "$trigger: handshake age ${handshakeAge}ms ≥ " +
                    "${staleHandshakeMs}ms → stale, re-racing",
            )
            val candidates = candidateProvider()
            if (candidates.isEmpty()) {
                logger.log('W', "re-race aborted: no candidates available")
                return
            }
            val ifaces = ifaceProvider()
            logger.log(
                'I',
                "re-race: ${candidates.size} candidate(s), " +
                    "${ifaces.size} local interface(s)",
            )
            val result = runner.connect(
                tunnelId = tunnelId,
                candidates = candidates,
                localInterfaces = ifaces,
                strictHotspot = strictHotspot,
                perCandidateTimeoutMs = perCandidateTimeoutMs,
                probeBudgetMs = probeBudgetMs,
            )
            onResult?.invoke(result)
        }
    }

    /** Stop responding to network changes; cancel any pending check.
     * Idempotent. */
    fun stop() {
        stopped = true
        pendingJob?.cancel()
        pendingJob = null
        pollJob?.cancel()
        pollJob = null
    }
}
