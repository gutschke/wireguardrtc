package com.gutschke.wgrtc.data

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.IOException
import java.util.Base64
import java.util.concurrent.atomic.AtomicInteger

/**
 * Behaviour of [JoinerWgRunner]: parallel to [HostModeBackend]
 * but for joiner-mode tunnels. Drives `wgbridge` in TUN-fd mode
 * — the kernel TUN (from `VpnService.Builder.establish()`) is the
 * cleartext side, wireguard-go drives encryption end-to-end. No
 * userspace netstack, no listener APIs.
 *
 * Tests use a fake [WgBridgeBackend] so the JNI never loads;
 * happy-path JNI lifecycle is covered by the instrumented test
 * suite under `app/src/androidTest/`.
 */
class JoinerWgRunnerTest {

    private val privKey = ByteArray(32) { (it + 1).toByte() }
    private val privB64 = Base64.getEncoder().encodeToString(privKey)
    private val privHex = privKey.joinToString("") { "%02x".format(it) }
    private val pubB64 = Base64.getEncoder().encodeToString(ByteArray(32) { 0xAA.toByte() })

    private fun sampleConfig(endpoint: String = "192.0.2.1:51820") = """
        [Interface]
        PrivateKey = $privB64
        Address = 10.99.0.2/32

        [Peer]
        PublicKey = $pubB64
        AllowedIPs = 10.99.0.0/24
        Endpoint = $endpoint
        PersistentKeepalive = 25
    """.trimIndent()

    @Test fun `start opens backend with provided fd+mtu and applies UAPI`() {
        val backend = HookedBackend()
        val factory = HookedFactory(backend)
        val runner = JoinerWgRunner(factory)
        runner.start(tunFd = 42, mtu = 1420, wgQuickConfig = sampleConfig())
        assertEquals(listOf(42 to 1420), factory.opens)
        // Initial UAPI should contain the joiner's private_key in
        // hex form + the peer's endpoint.
        val uapi = backend.uapiCalls.single()
        assertTrue(uapi.contains("private_key=$privHex"), uapi)
        assertTrue(uapi.contains("endpoint=192.0.2.1:51820"), uapi)
        assertTrue(uapi.contains("replace_peers=true"), uapi)
        assertTrue(runner.isRunning)
    }

    @Test fun `start propagates the protector to the backend`() {
        val backend = HookedBackend()
        val protector = WgFdProtector { it > 0 }
        val runner = JoinerWgRunner(HookedFactory(backend), protector = protector)
        runner.start(tunFd = 42, mtu = 1420, wgQuickConfig = sampleConfig())
        assertEquals(listOf<WgFdProtector?>(protector), backend.protectors)
    }

    @Test fun `start failure cleans up the backend`() {
        // Backend whose first configureUapi throws — runner should
        // close the freshly-opened backend so we don't leak it.
        val backend = HookedBackend(uapiError = IOException("bad uapi"))
        val factory = HookedFactory(backend)
        val runner = JoinerWgRunner(factory)
        assertThrows(IOException::class.java) {
            runner.start(tunFd = 42, mtu = 1420, wgQuickConfig = sampleConfig())
        }
        assertEquals(1, backend.closeCount.get())
        assertFalse(runner.isRunning)
    }

    @Test fun `reconfigure pushes a fresh UAPI without re-opening`() {
        val backend = HookedBackend()
        val factory = HookedFactory(backend)
        val runner = JoinerWgRunner(factory)
        runner.start(tunFd = 42, mtu = 1420, wgQuickConfig = sampleConfig("192.0.2.1:51820"))
        runner.reconfigure(sampleConfig("198.51.100.5:51820"))
        // Two UAPI calls, one factory open.
        assertEquals(2, backend.uapiCalls.size)
        assertEquals(1, factory.opens.size)
        // Newest UAPI carries the new endpoint.
        assertTrue(backend.uapiCalls[1].contains("endpoint=198.51.100.5:51820"))
        // Both UAPIs include replace_peers=true so revoke / endpoint
        // changes don't leave stale wireguard-go state.
        assertTrue(backend.uapiCalls.all { it.contains("replace_peers=true") })
    }

    @Test fun `reconfigure before start throws`() {
        val backend = HookedBackend()
        val runner = JoinerWgRunner(HookedFactory(backend))
        assertThrows(IllegalStateException::class.java) {
            runner.reconfigure(sampleConfig())
        }
    }

    @Test fun `close is idempotent`() {
        val backend = HookedBackend()
        val runner = JoinerWgRunner(HookedFactory(backend))
        runner.start(tunFd = 42, mtu = 1420, wgQuickConfig = sampleConfig())
        runner.close()
        runner.close()
        runner.close()
        assertEquals(1, backend.closeCount.get())
        assertFalse(runner.isRunning)
    }

    @Test fun `snapshotStats returns null before start`() {
        val backend = HookedBackend()
        val runner = JoinerWgRunner(HookedFactory(backend))
        assertNull(runner.snapshotStats())
    }

    @Test fun `snapshotStats parses backend UAPI dump after start`() {
        val pubHex = "aa".repeat(32)
        val backend = HookedBackend(
            uapiDump = """
                listen_port=12345
                public_key=$pubHex
                last_handshake_time_sec=2000
                last_handshake_time_nsec=0
                tx_bytes=10
                rx_bytes=20
            """.trimIndent() + "\n"
        )
        val runner = JoinerWgRunner(HookedFactory(backend))
        runner.start(tunFd = 42, mtu = 1420, wgQuickConfig = sampleConfig())
        val stats = runner.snapshotStats()!!
        assertEquals(2_000_000L, stats.peers[pubB64]!!.lastHandshakeEpochMs)
        assertEquals(20L, stats.totalRxBytes)
        assertEquals(10L, stats.totalTxBytes)
    }

    /** Fake matching HostModeBackendTest's HookedBackend shape. */
    private class HookedBackend(
        private val uapiError: Exception? = null,
        private val uapiDump: String = "",
    ) : WgBridgeBackend {
        val uapiCalls = mutableListOf<String>()
        val protectors = mutableListOf<WgFdProtector?>()
        val closeCount = AtomicInteger(0)
        @Volatile private var closed = false

        override fun configureUapi(uapi: String) {
            uapiError?.let { throw it }
            uapiCalls += uapi
        }
        override fun listenTcp(port: Int, acceptor: WgTcpAcceptor) =
            error("joiner doesn't expose listenTcp")
        override fun listenUdp(port: Int, receiver: WgUdpReceiver): WgUdpSink =
            error("joiner doesn't expose listenUdp")
        override fun setFdProtector(protector: WgFdProtector?) {
            if (closed) return
            protectors += protector
        }
        override fun snapshotUapi(): String = if (closed) "" else uapiDump
        override fun close() {
            if (closed) return
            closed = true
            closeCount.incrementAndGet()
        }
    }

    private class HookedFactory(private val backend: WgBridgeBackend) :
        (Int, Int) -> WgBridgeBackend {
        val opens = mutableListOf<Pair<Int, Int>>()
        override fun invoke(fd: Int, mtu: Int): WgBridgeBackend {
            opens += fd to mtu
            return backend
        }
    }
}
