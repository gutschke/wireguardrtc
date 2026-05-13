package com.gutschke.wgrtc.data

import android.util.Log
import com.gutschke.wgrtc.signalling.EndpointUpdate
import com.gutschke.wgrtc.signalling.formatEndpoint
import com.gutschke.wgrtc.signalling.TunnelEndpointController
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * The minimum surface [WgBridgeTunnelEndpointController] needs from
 * an underlying joiner runner. Pulled out as an interface so the
 * controller is testable with a fake — the concrete runner
 * ([JoinerWgRunner]) loads the JNI on first instantiation, which we
 * don't want in JVM unit tests.
 */
interface JoinerEndpointReconfigurer {
    /** In-place reconfigure via UAPI. No DOWN+UP cycle. */
    fun reconfigure(wgQuickConfig: String)

    /** Snapshot of wireguard-go's current state. Returns null
     * when not running. */
    fun snapshotStats(): UapiStats?

    /** Idempotent shutdown. */
    fun close()
}

// JoinerWgRunner is a JoinerEndpointReconfigurer (its public API
// already matches the interface). The mapping is a thin extension
// rather than an `implements` clause so JoinerWgRunner stays
// independent of the signalling abstraction.
fun JoinerWgRunner.asEndpointReconfigurer(): JoinerEndpointReconfigurer =
    object : JoinerEndpointReconfigurer {
        override fun reconfigure(wgQuickConfig: String) =
            this@asEndpointReconfigurer.reconfigure(wgQuickConfig)
        override fun snapshotStats(): UapiStats? =
            this@asEndpointReconfigurer.snapshotStats()
        override fun close() = this@asEndpointReconfigurer.close()
    }

/**
 * Joiner-mode [TunnelEndpointController] — drives the candidate
 * race via wgbridge_native's UAPI surface. The TUN-fd path
 * supports in-place endpoint updates, so this controller skips
 * the DOWN+UP cycle the (deleted) wireguard-android path needed.
 *
 * Lifecycle assumption: the [runner] has already been started by
 * the caller (the ViewModel's connect coroutine, which sequences
 * VpnService bring-up → JoinerWgRunner.start → ConnectionRunner
 * race). This controller doesn't open the runner — only mutates
 * its endpoint and reads its stats. [bringDown] closes the
 * runner; the caller is responsible for opening a fresh one for
 * the next connect attempt.
 */
class WgBridgeTunnelEndpointController(
    private val runner: JoinerEndpointReconfigurer,
    private val hub: ListenerHub,
) : TunnelEndpointController {

    override suspend fun setEndpoint(
        tunnelId: String,
        candidate: EndpointUpdate,
        egressInterface: String?,
    ) = withContext(Dispatchers.IO) {
        val tunnels = hub.loadTunnels()
        val tunnel = tunnels.firstOrNull { it.id == tunnelId }
            ?: error("setEndpoint: no tunnel with id $tunnelId")
        val newEndpoint = formatEndpoint(candidate.ip, candidate.port)
        val newConfigText = replaceEndpointLine(tunnel.configText, newEndpoint)
        // In-place reconfigure. wireguard-go's IpcSet replaces the
        // peer's endpoint without disturbing the active session
        // when the new value is the same as the old, or initiates
        // a fresh handshake when it differs. No DOWN+UP needed.
        runner.reconfigure(newConfigText)
        // Persist rule: public/STUN winners persist; same-subnet
        // (LAN) winners stay live-only so a future cross-network
        // reconnect doesn't fall back to a dead LAN address. See
        // [shouldPersistRaceWinner].
        if (shouldPersistRaceWinner(egressInterface)) {
            hub.rewriteEndpoint(tunnelId, newEndpoint)
        } else {
            Log.i("wgrtc-runner",
                "race winner $newEndpoint is same-subnet (egress=" +
                "$egressInterface); using live but not persisting")
        }
        Unit
    }

    override suspend fun latestHandshakeMs(): Long = withContext(Dispatchers.IO) {
        runner.snapshotStats()?.mostRecentHandshakeEpochMs ?: 0L
    }

    override suspend fun bringDown() = withContext(Dispatchers.IO) {
        runner.close()
    }
}

/**
 * Decide whether a race-winner endpoint should be written back to
 * the persisted wg-quick config.
 *
 * Universal addresses (no local-interface match — [egressInterface]
 * is null, typically a public/STUN-derived IP) MUST be persisted so
 * the next process startup can connect even with an empty listener
 * cache.
 *
 * Same-subnet (LAN) addresses MUST NOT be persisted: they're
 * environment-specific. Persisting one would brick the tunnel after
 * the user moves to a different network — the persisted address
 * becomes unreachable and there is no public-IP fallback. Pinned by
 * [ShouldPersistRaceWinnerTest]; caught a deadlock during the
 * 2026-05-08 debug session.
 */
fun shouldPersistRaceWinner(egressInterface: String?): Boolean =
    egressInterface == null

