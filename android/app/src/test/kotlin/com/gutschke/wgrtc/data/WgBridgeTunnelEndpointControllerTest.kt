package com.gutschke.wgrtc.data

import com.gutschke.wgrtc.signalling.EndpointUpdate
import com.gutschke.wgrtc.signalling.SignalWakeSender
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.File
import java.util.Base64

/**
 * Behavior of [WgBridgeTunnelEndpointController]. Drives the
 * candidate race for joiner-mode tunnels via [JoinerWgRunner]
 * (wgbridge / TUN-fd) instead of the legacy GoBackend.
 *
 * **Key contract differences vs. RealTunnelEndpointController:**
 *
 * - **No DOWN+UP cycle.** wgbridge's `IpcSet` handles in-place
 * endpoint updates. setEndpoint just renders fresh UAPI and
 * reconfigures.
 * - **Stats via UAPI dump.** No per-peer Statistics object —
 * we parse `last_handshake_time_sec` from the bridge's
 * SnapshotUAPI output.
 * - **bringDown closes the runner**. The next connect attempt
 * needs a fresh runner with a new VpnService TUN fd; the
 * controller doesn't manage that lifecycle (the ViewModel
 * does, around the controller).
 *
 * Tests use a fake [JoinerWgRunner]-shaped surface — exercising
 * the controller's contract without requiring the JNI.
 */
class WgBridgeTunnelEndpointControllerTest {

    private val privKey = ByteArray(32) { (it + 1).toByte() }
    private val privB64 = Base64.getEncoder().encodeToString(privKey)
    private val pubB64 = Base64.getEncoder().encodeToString(ByteArray(32) { 0xAA.toByte() })

    private fun configText(endpoint: String) = """
        [Interface]
        PrivateKey = $privB64
        Address = 10.99.0.2/32

        [Peer]
        PublicKey = $pubB64
        AllowedIPs = 10.99.0.0/24
        Endpoint = $endpoint
        PersistentKeepalive = 25
    """.trimIndent()

    private fun setupHub(): Pair<ListenerHub, Tunnel> {
        val tmpDir = java.nio.file.Files.createTempDirectory("wgbridge-ctrl").toFile()
        tmpDir.deleteOnExit()
        val store = TunnelStore(File(tmpDir, "tunnels.json"))
        val tunnel = Tunnel(
            id = "j1",
            name = "joiner",
            configText = configText("192.0.2.1:51820"),
            source = Tunnel.Source.ENROLL,
        )
        store.save(listOf(tunnel))
        val sender = object : SignalWakeSender {
            override suspend fun sendWake(
                sendVia: suspend (String) -> Boolean,
                sigboxKey: ByteArray,
                dstRoutingId: String,
            ): Boolean = true
        }
        val hub = ListenerHub(store, sender, { System.currentTimeMillis() })
        return hub to tunnel
    }

    @Test
    fun `setEndpoint rewrites the persisted Endpoint line and reconfigures the runner`() = runBlocking<Unit> {
        val (hub, tunnel) = setupHub()
        val runner = FakeJoinerRunner()
        val ctrl = WgBridgeTunnelEndpointController(runner, hub)
        ctrl.setEndpoint(
            tunnel.id,
            EndpointUpdate("198.51.100.5", 51820, 0L),
            egressInterface = null,
        )
        // Runner saw the new wg-quick text via reconfigure().
        val reconfText = runner.reconfigureCalls.single()
        assertTrue(reconfText.contains("Endpoint = 198.51.100.5:51820"))
        assertTrue(reconfText.contains("PrivateKey = $privB64"))
        // Hub persisted the new endpoint (egressInterface=null →
        // public/STUN candidate → persist).
        val reloaded = hub.loadTunnels().single()
        assertTrue(reloaded.configText.contains("Endpoint = 198.51.100.5:51820"))
    }

    @Test
    fun `same-subnet winner does not get persisted to disk`() = runBlocking<Unit> {
        val (hub, tunnel) = setupHub()
        val runner = FakeJoinerRunner()
        val ctrl = WgBridgeTunnelEndpointController(runner, hub)
        ctrl.setEndpoint(
            tunnel.id,
            EndpointUpdate("10.99.42.5", 51820, 0L),
            egressInterface = "wlan0", // same-subnet match
        )
        // Live runner reconfigured...
        val reconfText = runner.reconfigureCalls.single()
        assertTrue(reconfText.contains("Endpoint = 10.99.42.5:51820"))
        // ...but disk still has the original universally-reachable
        // endpoint as the next-process-startup fallback.
        val reloaded = hub.loadTunnels().single()
        assertTrue(reloaded.configText.contains("Endpoint = 192.0.2.1:51820"))
    }

    @Test
    fun `latestHandshakeMs reads the most-recent peer handshake from the runner snapshot`() = runBlocking<Unit> {
        val (hub, _) = setupHub()
        val runner = FakeJoinerRunner(
            snapshotResult = UapiStats(
                listenPort = 12345,
                totalRxBytes = 1L,
                totalTxBytes = 2L,
                peers = mapOf(pubB64 to PeerStats(
                    rxBytes = 1L, txBytes = 2L,
                    lastHandshakeEpochMs = 1_700_000_000_500L,
                )),
            ),
        )
        val ctrl = WgBridgeTunnelEndpointController(runner, hub)
        assertEquals(1_700_000_000_500L, ctrl.latestHandshakeMs())
    }

    @Test
    fun `latestHandshakeMs returns 0 when no handshake has completed`() = runBlocking<Unit> {
        val (hub, _) = setupHub()
        val runner = FakeJoinerRunner(
            snapshotResult = UapiStats(
                peers = mapOf(pubB64 to PeerStats(
                    rxBytes = 0L, txBytes = 0L, lastHandshakeEpochMs = null,
                )),
            ),
        )
        val ctrl = WgBridgeTunnelEndpointController(runner, hub)
        assertEquals(0L, ctrl.latestHandshakeMs())
    }

    @Test
    fun `bringDown closes the runner`() = runBlocking<Unit> {
        val (hub, _) = setupHub()
        val runner = FakeJoinerRunner()
        val ctrl = WgBridgeTunnelEndpointController(runner, hub)
        ctrl.bringDown()
        assertTrue(runner.closed)
    }

    @Test
    fun `setEndpoint on a missing tunnel id throws`() = runBlocking<Unit> {
        val (hub, _) = setupHub()
        val runner = FakeJoinerRunner()
        val ctrl = WgBridgeTunnelEndpointController(runner, hub)
        try {
            ctrl.setEndpoint("nonexistent", EndpointUpdate("1.2.3.4", 51820, 0L), null)
            error("expected exception")
        } catch (_: IllegalStateException) { /* expected */ }
    }

    /** Fake of just the surface this controller cares about. */
    private class FakeJoinerRunner(
        private val snapshotResult: UapiStats? = null,
    ) : JoinerEndpointReconfigurer {
        val reconfigureCalls = mutableListOf<String>()
        var closed: Boolean = false
            private set

        override fun reconfigure(wgQuickConfig: String) {
            reconfigureCalls += wgQuickConfig
        }
        override fun snapshotStats(): UapiStats? = snapshotResult
        override fun close() { closed = true }
    }
}
