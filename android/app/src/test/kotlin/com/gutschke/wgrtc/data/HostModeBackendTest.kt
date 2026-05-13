package com.gutschke.wgrtc.data

import com.gutschke.wgrtc.data.HostModeUapi.Peer
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.IOException
import java.util.Base64
import java.util.concurrent.atomic.AtomicInteger

/**
 * Behavior of the host backend: owns at most one
 * [HostModeRunner] at a time, exposes start / stop / reconfigure +
 * a per-pubkey stats snapshot. All tests use a fake
 * [WgBridgeBackend] so the Go runtime never loads.
 */
class HostModeBackendTest {

    private val parentJob = SupervisorJob()
    private val parentScope = CoroutineScope(Dispatchers.Default + parentJob)

    @AfterEach fun tearDown() { parentJob.cancel() }

    private val privKey32 = ByteArray(32) { (it + 1).toByte() }
    private val privB64 = Base64.getEncoder().encodeToString(privKey32)
    private val peerKey = ByteArray(32) { (0xaa).toByte() }
    private val peerB64 = Base64.getEncoder().encodeToString(peerKey)

    private fun hostTunnel(
        id: String = "t1",
        listenPort: Int = 51820,
        peers: List<Peer> = listOf(Peer(peerB64, "10.99.0.2/32")),
        configText: String = """
            [Interface]
            PrivateKey = $privB64
            Address = 10.99.0.1/24
            ListenPort = $listenPort

            [Peer]
            PublicKey = $peerB64
            AllowedIPs = 10.99.0.2/32
        """.trimIndent(),
    ) = Tunnel(
        id = id,
        name = "host-$id",
        configText = configText,
        source = Tunnel.Source.HOST_MODE,
        hostMode = HostModeConfig(
            subnet = "10.99.0.0/24",
            enrolledPeers = peers.map {
                EnrolledPeer(
                    pubkeyB64 = it.publicKeyB64,
                    assignedIp = it.allowedIp.substringBefore("/"),
                    nameHint = "guest",
                    enrolledAtMs = 1L,
                )
            },
        ),
    )

    @Test
    fun `start opens backend with privkey and listenPort and configures UAPI`() = runBlocking<Unit> {
        val backend = HookedBackend()
        val factory = HookedFactory(backend)
        val be = HostModeBackend(factory, parentScope)
        be.start(hostTunnel(listenPort = 51821))
        assertEquals(1, factory.opens.size)
        val (addr, mtu, port) = factory.opens.single()
        assertEquals("10.99.0.1", addr)
        assertEquals(1420, mtu)
        assertEquals(51821, port)
        val uapi = backend.uapiCalls.single()
        assertTrue(uapi.contains("private_key="))
        assertTrue(uapi.contains("listen_port=51821"))
        assertTrue(uapi.contains("allowed_ip=10.99.0.2/32"))
        // TCP + UDP catchall forwarders are installed on
        // every start. Without these the host accepts handshakes
        // but drops everything addressed to a non-local IP.
        // (ICMP forwarding to non-local addrs is NOT wired — see
        // doc/wireguard-runtime-architecture.md §6 for the
        // attempt + why it was reverted.)
        assertEquals(1, backend.tcpCatchallInstalls.get())
        assertEquals(1, backend.udpCatchallInstalls.get())
    }

    @Test
    fun `stop closes both catchall forwarders`() = runBlocking<Unit> {
        val backend = HookedBackend()
        val be = HostModeBackend(HookedFactory(backend), parentScope)
        be.start(hostTunnel())
        // TCP + UDP catchalls installed on start.
        assertEquals(1, backend.tcpCatchallInstalls.get())
        assertEquals(1, backend.udpCatchallInstalls.get())
        // Host forwarder installed on start since the
        // production wiring derives a non-null subnet from
        // hostTunnel()'s `[Interface] Address = 10.99.0.1/24`.
        assertEquals(1, backend.hostForwarderInstalls.get())
        // teardown() calls HostModeRunner.stop(), which must close
        // all three AutoCloseables (TCP + UDP catchall + host
        // forwarder) BEFORE the bridge so a late dispatch from
        // gvisor can't land on a half-closed handler.
        be.teardown()
        assertEquals(3, backend.catchallCloses.get(),
            "TCP + UDP catchall + host forwarder must all be closed")
    }

    @Test
    fun `start while already running throws`() = runBlocking<Unit> {
        val backend = HookedBackend()
        val be = HostModeBackend(HookedFactory(backend), parentScope)
        be.start(hostTunnel())
        assertThrows(IllegalStateException::class.java) {
            runBlocking { be.start(hostTunnel(id = "t2")) }
        }
    }

    @Test
    fun `stop pauses the underlying backend without closing it`() = runBlocking<Unit> {
        val backend = HookedBackend()
        val be = HostModeBackend(HookedFactory(backend), parentScope)
        be.start(hostTunnel())
        be.stop()
        // do NOT close the backend — close+reopen of
        // wireguard-go in the same process triggers a fatal
        // Go-runtime panic. Pause via UAPI keeps the bridge alive
        // for the next start().
        assertEquals(0, backend.closeCount.get())
        assertNull(be.activeTunnelId)
        // The pause UAPI must have been issued.
        val pauseUapi = backend.uapiCalls.last()
        assertTrue(pauseUapi.contains("replace_peers=true"))
        assertTrue(pauseUapi.contains("listen_port=0"))
    }

    @Test
    fun `stop is idempotent`() = runBlocking<Unit> {
        val backend = HookedBackend()
        val be = HostModeBackend(HookedFactory(backend), parentScope)
        be.start(hostTunnel())
        be.stop()
        val callsAfterFirstStop = backend.uapiCalls.size
        be.stop()
        be.stop()
        // Subsequent stops do nothing (pause already issued).
        assertEquals(callsAfterFirstStop, backend.uapiCalls.size)
        assertEquals(0, backend.closeCount.get())
    }

    @Test
    fun `stop before start is a no-op`() = runBlocking<Unit> {
        val backend = HookedBackend()
        val be = HostModeBackend(HookedFactory(backend), parentScope)
        be.stop()
        assertEquals(0, backend.closeCount.get())
        assertEquals(0, backend.uapiCalls.size)
    }

    @Test
    fun `start after stop reuses the existing bridge instead of opening a new one`() = runBlocking<Unit> {
        val backend = HookedBackend()
        val factory = HookedFactory(backend)
        val be = HostModeBackend(factory, parentScope)
        be.start(hostTunnel())
        be.stop()
        be.start(hostTunnel())
        // The factory was only consulted once: reuses the
        // bridge across user-initiated stop/start cycles to avoid
        // the wireguard-go close+recreate panic.
        assertEquals(1, factory.opens.size,
            "second start() must NOT open a fresh bridge — pause/resume preserves the original")
        // Three UAPI calls: initial start, pause, resume.
        assertEquals(3, backend.uapiCalls.size)
        assertEquals("t1", be.activeTunnelId)
    }

    @Test
    fun `start with a different tunnel id closes the old bridge before opening a new one`() = runBlocking<Unit> {
        val backend = HookedBackend()
        val factory = HookedFactory(backend)
        val be = HostModeBackend(factory, parentScope)
        be.start(hostTunnel(id = "t1"))
        be.stop()
        // Different tunnel — the prior bridge can't be reused
        // (different localAddr / privkey would need a fresh
        // wireguard-go device). Accept the close+recreate
        // crash risk for this less-common path.
        be.start(hostTunnel(id = "t2"))
        assertEquals(2, factory.opens.size)
        assertEquals(1, backend.closeCount.get())
        assertEquals("t2", be.activeTunnelId)
    }

    @Test
    fun `teardown explicitly closes the bridge for app shutdown`() = runBlocking<Unit> {
        val backend = HookedBackend()
        val be = HostModeBackend(HookedFactory(backend), parentScope)
        be.start(hostTunnel())
        be.teardown()
        assertEquals(1, backend.closeCount.get())
        assertNull(be.activeTunnelId)
    }

    @Test
    fun `reconfigure UAPI includes replace_peers=true so revoked peers actually disappear`() = runBlocking<Unit> {
        // Regression: without `replace_peers=true` wireguard-go's
        // IpcSet is a *merge* — the previous peer set stays alive.
        // The user observed ChromeOS still showed "Connected" against
        // a peer that had just been revoked because the host's wg-go
        // never dropped the session.
        val backend = HookedBackend()
        val be = HostModeBackend(HookedFactory(backend), parentScope)
        be.start(hostTunnel())
        be.reconfigure(hostTunnel())
        val reconfUapi = backend.uapiCalls.last()
        assertTrue(reconfUapi.contains("replace_peers=true"),
            "reconfigure UAPI must include replace_peers=true to drop revoked peers")
    }

    @Test
    fun `reconfigure pushes a fresh UAPI string without closing the backend`() = runBlocking<Unit> {
        val backend = HookedBackend()
        val be = HostModeBackend(HookedFactory(backend), parentScope)
        be.start(hostTunnel())
        // Add a second enrolled peer; reconfigure should push a UAPI
        // that includes both allowed-ip lines.
        val peer2B64 = Base64.getEncoder().encodeToString(ByteArray(32) { (0xbb).toByte() })
        val updated = hostTunnel().let { t ->
            t.copy(
                hostMode = t.hostMode!!.copy(
                    enrolledPeers = t.hostMode.enrolledPeers + EnrolledPeer(
                        pubkeyB64 = peer2B64,
                        assignedIp = "10.99.0.3",
                        nameHint = "g2",
                        enrolledAtMs = 2L,
                    ),
                ),
                configText = t.configText + "\n[Peer]\nPublicKey = $peer2B64\nAllowedIPs = 10.99.0.3/32\n",
            )
        }
        be.reconfigure(updated)
        assertEquals(2, backend.uapiCalls.size, "first start UAPI + reconfigure UAPI")
        assertTrue(backend.uapiCalls[1].contains("allowed_ip=10.99.0.3/32"))
        assertTrue(backend.uapiCalls[1].contains("allowed_ip=10.99.0.2/32"))
        assertEquals(0, backend.closeCount.get(), "reconfigure must not close the backend")
    }

    @Test
    fun `reconfigure when not running is a silent no-op`() = runBlocking<Unit> {
        val backend = HookedBackend()
        val be = HostModeBackend(HookedFactory(backend), parentScope)
        be.reconfigure(hostTunnel())
        assertEquals(0, backend.uapiCalls.size)
    }

    @Test
    fun `reconfigure for a different tunnel id is rejected`() = runBlocking<Unit> {
        val backend = HookedBackend()
        val be = HostModeBackend(HookedFactory(backend), parentScope)
        be.start(hostTunnel(id = "t1"))
        be.reconfigure(hostTunnel(id = "t2"))
        // Only the initial start UAPI fired; the t2 reconfigure was
        // ignored because t1 is the active tunnel.
        assertEquals(1, backend.uapiCalls.size)
    }

    @Test
    fun `start failure cleans up and leaves backend stopped`() = runBlocking<Unit> {
        val backend = HookedBackend(uapiError = IOException("bad config"))
        val be = HostModeBackend(HookedFactory(backend), parentScope)
        assertThrows(IOException::class.java) {
            runBlocking { be.start(hostTunnel()) }
        }
        assertEquals(1, backend.closeCount.get())
        assertNull(be.activeTunnelId)
    }

    @Test
    fun `activeTunnelId tracks lifecycle`() = runBlocking<Unit> {
        val backend = HookedBackend()
        val be = HostModeBackend(HookedFactory(backend), parentScope)
        assertNull(be.activeTunnelId)
        be.start(hostTunnel(id = "abc"))
        assertEquals("abc", be.activeTunnelId)
        be.stop()
        assertNull(be.activeTunnelId)
    }

    @Test
    fun `setProtector before start is a no-op`() = runBlocking<Unit> {
        val backend = HookedBackend()
        val be = HostModeBackend(HookedFactory(backend), parentScope)
        be.setProtector(WgFdProtector { false })
        assertEquals(0, backend.protectors.size)
    }

    @Test
    fun `setProtector after start forwards to backend`() = runBlocking<Unit> {
        val backend = HookedBackend()
        val be = HostModeBackend(HookedFactory(backend), parentScope)
        be.start(hostTunnel())
        val p = WgFdProtector { it > 0 }
        be.setProtector(p)
        assertEquals(listOf<WgFdProtector?>(p), backend.protectors)
    }

    @Test
    fun `snapshotStats returns null when no tunnel is running`() = runBlocking<Unit> {
        val be = HostModeBackend(HookedFactory(HookedBackend()), parentScope)
        org.junit.jupiter.api.Assertions.assertNull(be.snapshotStats())
    }

    @Test
    fun `snapshotStats parses backend's UAPI dump after start`() = runBlocking<Unit> {
        val pubHex = "01".repeat(32)
        val pubB64 = Base64.getEncoder().encodeToString(ByteArray(32) { 1.toByte() })
        val backend = HookedBackend(
            uapiDump = """
                listen_port=51820
                public_key=$pubHex
                last_handshake_time_sec=2000
                last_handshake_time_nsec=0
                tx_bytes=10
                rx_bytes=20
            """.trimIndent() + "\n"
        )
        val be = HostModeBackend(HookedFactory(backend), parentScope)
        be.start(hostTunnel())
        val stats = be.snapshotStats()!!
        assertEquals(2_000_000L, stats.peers[pubB64]!!.lastHandshakeEpochMs)
        assertEquals(20L, stats.totalRxBytes)
        assertEquals(10L, stats.totalTxBytes)
    }

    @Test
    fun `subnet other than 10_99_0_0_24 is honored for localAddr`() = runBlocking<Unit> {
        val backend = HookedBackend()
        val factory = HookedFactory(backend)
        val be = HostModeBackend(factory, parentScope)
        // A host whose [Interface] Address is 192.168.42.1/24 should
        // open the backend at that address — the WG-side IP must
        // match the joiner's [Peer] Endpoint = ... AllowedIPs entry.
        val cfg = """
            [Interface]
            PrivateKey = $privB64
            Address = 192.168.42.1/24
            ListenPort = 51820

            [Peer]
            PublicKey = $peerB64
            AllowedIPs = 192.168.42.2/32
        """.trimIndent()
        be.start(hostTunnel(configText = cfg).let {
            it.copy(hostMode = it.hostMode!!.copy(
                subnet = "192.168.42.0/24",
                enrolledPeers = listOf(
                    EnrolledPeer(peerB64, "192.168.42.2", "g", 1L))
            ))
        })
        val (addr, _, _) = factory.opens.single()
        assertEquals("192.168.42.1", addr)
    }

    /** Backend fake — captures UAPI calls + protector swaps. */
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
        override fun listenTcp(port: Int, acceptor: WgTcpAcceptor) {}

        // HostModeBackend now defaults to installing catchall
        // forwarders on every start. The unit-test fake doesn't
        // need real catchall behavior — it just records that the
        // install happened so tests can assert lifecycle if they
        // want to. Returning a no-op AutoCloseable satisfies the
        // ownership contract.
        val tcpCatchallInstalls = AtomicInteger(0)
        val udpCatchallInstalls = AtomicInteger(0)
        val catchallCloses = AtomicInteger(0)
        override fun installTcpCatchall(
            handler: TcpForwarderHandler,
            scope: kotlinx.coroutines.CoroutineScope,
        ): AutoCloseable {
            tcpCatchallInstalls.incrementAndGet()
            return AutoCloseable { catchallCloses.incrementAndGet() }
        }
        override fun installUdpCatchall(
            handler: UdpForwarderHandler,
            scope: kotlinx.coroutines.CoroutineScope,
        ): AutoCloseable {
            udpCatchallInstalls.incrementAndGet()
            return AutoCloseable { catchallCloses.incrementAndGet() }
        }

        val hostForwarderInstalls = AtomicInteger(0)
        var lastHostForwarderSubnet: String? = null
        override fun installHostForwarder(peerSubnet: String): AutoCloseable {
            hostForwarderInstalls.incrementAndGet()
            lastHostForwarderSubnet = peerSubnet
            return AutoCloseable { catchallCloses.incrementAndGet() }
        }

        override fun listenUdp(port: Int, receiver: WgUdpReceiver): WgUdpSink =
            object : WgUdpSink {
                override fun sendTo(peerAddr: String, data: ByteArray) {}
                override fun close() {}
            }
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

    private class HookedFactory(private val backend: WgBridgeBackend) : WgBridgeBackendFactory {
        val opens = mutableListOf<Triple<String, Int, Int>>()
        override fun open(localAddr: String, mtu: Int, listenPort: Int): WgBridgeBackend {
            opens += Triple(localAddr, mtu, listenPort)
            return backend
        }
    }
}
