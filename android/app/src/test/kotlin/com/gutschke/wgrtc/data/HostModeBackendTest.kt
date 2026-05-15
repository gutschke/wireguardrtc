package com.gutschke.wgrtc.data

import com.gutschke.wgrtc.data.HostModeUapi.Peer
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.take
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.async
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
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
 * Behavior of the host backend: owns N [HostModeRunner] slots keyed
 * by `tunnelId`, exposes start / stop / teardown / reconfigure + a
 * per-tunnel stats snapshot. All tests use a fake [WgBridgeBackend]
 * so the Go runtime never loads.
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
        val factory = HookedFactory { backend }
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
    fun `teardown closes both catchall forwarders`() = runBlocking<Unit> {
        val backend = HookedBackend()
        val be = HostModeBackend(HookedFactory { backend }, parentScope)
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
        be.teardown("t1")
        assertEquals(3, backend.catchallCloses.get(),
            "TCP + UDP catchall + host forwarder must all be closed")
    }

    @Test
    fun `stop pauses the underlying backend without closing it`() = runBlocking<Unit> {
        val backend = HookedBackend()
        val be = HostModeBackend(HookedFactory { backend }, parentScope)
        be.start(hostTunnel())
        be.stop("t1")
        // do NOT close the backend — close+reopen of
        // wireguard-go in the same process triggers a fatal
        // Go-runtime panic. Pause via UAPI keeps the bridge alive
        // for the next start().
        assertEquals(0, backend.closeCount.get())
        assertTrue(be.activeTunnelIds.value.isEmpty())
        // The pause UAPI must have been issued.
        val pauseUapi = backend.uapiCalls.last()
        assertTrue(pauseUapi.contains("replace_peers=true"))
        assertTrue(pauseUapi.contains("listen_port=0"))
    }

    @Test
    fun `stop is idempotent`() = runBlocking<Unit> {
        val backend = HookedBackend()
        val be = HostModeBackend(HookedFactory { backend }, parentScope)
        be.start(hostTunnel())
        be.stop("t1")
        val callsAfterFirstStop = backend.uapiCalls.size
        be.stop("t1")
        be.stop("t1")
        // Subsequent stops do nothing (pause already issued).
        assertEquals(callsAfterFirstStop, backend.uapiCalls.size)
        assertEquals(0, backend.closeCount.get())
    }

    @Test
    fun `stop before start is a no-op`() = runBlocking<Unit> {
        val backend = HookedBackend()
        val be = HostModeBackend(HookedFactory { backend }, parentScope)
        be.stop("t1")
        assertEquals(0, backend.closeCount.get())
        assertEquals(0, backend.uapiCalls.size)
    }

    @Test
    fun `start after stop reuses the existing bridge instead of opening a new one`() = runBlocking<Unit> {
        val backend = HookedBackend()
        val factory = HookedFactory { backend }
        val be = HostModeBackend(factory, parentScope)
        be.start(hostTunnel())
        be.stop("t1")
        be.start(hostTunnel())
        // The factory was only consulted once: reuses the
        // bridge across user-initiated stop/start cycles to avoid
        // the wireguard-go close+recreate panic.
        assertEquals(1, factory.opens.size,
            "second start() must NOT open a fresh bridge — pause/resume preserves the original")
        // Three UAPI calls: initial start, pause, resume.
        assertEquals(3, backend.uapiCalls.size)
        assertEquals(setOf("t1"), be.activeTunnelIds.value)
    }

    @Test
    fun `teardown explicitly closes the bridge for app shutdown`() = runBlocking<Unit> {
        val backend = HookedBackend()
        val be = HostModeBackend(HookedFactory { backend }, parentScope)
        be.start(hostTunnel())
        be.teardown("t1")
        assertEquals(1, backend.closeCount.get())
        assertTrue(be.activeTunnelIds.value.isEmpty())
    }

    @Test
    fun `reconfigure UAPI includes replace_peers=true so revoked peers actually disappear`() = runBlocking<Unit> {
        // Regression: without `replace_peers=true` wireguard-go's
        // IpcSet is a *merge* — the previous peer set stays alive.
        // The user observed ChromeOS still showed "Connected" against
        // a peer that had just been revoked because the host's wg-go
        // never dropped the session.
        val backend = HookedBackend()
        val be = HostModeBackend(HookedFactory { backend }, parentScope)
        be.start(hostTunnel())
        be.reconfigure(hostTunnel())
        val reconfUapi = backend.uapiCalls.last()
        assertTrue(reconfUapi.contains("replace_peers=true"),
            "reconfigure UAPI must include replace_peers=true to drop revoked peers")
    }

    @Test
    fun `reconfigure pushes a fresh UAPI string without closing the backend`() = runBlocking<Unit> {
        val backend = HookedBackend()
        val be = HostModeBackend(HookedFactory { backend }, parentScope)
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
        val be = HostModeBackend(HookedFactory { backend }, parentScope)
        be.reconfigure(hostTunnel())
        assertEquals(0, backend.uapiCalls.size)
    }

    @Test
    fun `reconfigure for a tunnel id that's not running is a silent no-op`() = runBlocking<Unit> {
        val backend = HookedBackend()
        val be = HostModeBackend(HookedFactory { backend }, parentScope)
        be.start(hostTunnel(id = "t1"))
        be.reconfigure(hostTunnel(id = "t2"))
        // Only the initial start UAPI fired; the t2 reconfigure was
        // ignored because no slot for t2 exists.
        assertEquals(1, backend.uapiCalls.size)
    }

    @Test
    fun `start failure cleans up and leaves backend stopped`() = runBlocking<Unit> {
        val backend = HookedBackend(uapiError = IOException("bad config"))
        val be = HostModeBackend(HookedFactory { backend }, parentScope)
        assertThrows(IOException::class.java) {
            runBlocking { be.start(hostTunnel()) }
        }
        assertEquals(1, backend.closeCount.get())
        assertTrue(be.activeTunnelIds.value.isEmpty())
    }

    @Test
    fun `activeTunnelIds tracks lifecycle`() = runBlocking<Unit> {
        val backend = HookedBackend()
        val be = HostModeBackend(HookedFactory { backend }, parentScope)
        assertTrue(be.activeTunnelIds.value.isEmpty())
        be.start(hostTunnel(id = "abc"))
        assertEquals(setOf("abc"), be.activeTunnelIds.value)
        be.stop("abc")
        assertTrue(be.activeTunnelIds.value.isEmpty())
    }

    @Test
    fun `setProtector before start is a no-op`() = runBlocking<Unit> {
        val backend = HookedBackend()
        val be = HostModeBackend(HookedFactory { backend }, parentScope)
        be.setProtector(WgFdProtector { false })
        assertEquals(0, backend.protectors.size)
    }

    @Test
    fun `setProtector after start forwards to backend`() = runBlocking<Unit> {
        val backend = HookedBackend()
        val be = HostModeBackend(HookedFactory { backend }, parentScope)
        be.start(hostTunnel())
        val p = WgFdProtector { it > 0 }
        be.setProtector(p)
        assertEquals(listOf<WgFdProtector?>(p), backend.protectors)
    }

    @Test
    fun `snapshotStats returns null when no tunnel is running`() = runBlocking<Unit> {
        val be = HostModeBackend(HookedFactory { HookedBackend() }, parentScope)
        assertNull(be.snapshotStats("t1"))
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
        val be = HostModeBackend(HookedFactory { backend }, parentScope)
        be.start(hostTunnel())
        val stats = be.snapshotStats("t1")!!
        assertEquals(2_000_000L, stats.peers[pubB64]!!.lastHandshakeEpochMs)
        assertEquals(20L, stats.totalRxBytes)
        assertEquals(10L, stats.totalTxBytes)
    }

    @Test
    fun `subnet other than 10_99_0_0_24 is honored for localAddr`() = runBlocking<Unit> {
        val backend = HookedBackend()
        val factory = HookedFactory { backend }
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

    @Test
    fun `V6_H1 dual-stack Interface Address lines flow comma-joined to the factory`() = runBlocking<Unit> {
        val backend = HookedBackend()
        val factory = HookedFactory { backend }
        val be = HostModeBackend(factory, parentScope)
        // When the host's tunnel config has BOTH a v4 and a v6
        // Address line, the backend factory must see them joined
        // with a comma so wgbridge_native's parseLocalAddrs splits
        // them back out and registers both protocols on the gvisor
        // netstack.  Pre-V6.H1 the v6 line was silently dropped
        // (parseInterfaceField returns only the first match).
        val cfg = """
            [Interface]
            PrivateKey = $privB64
            Address = 10.99.0.1/24
            Address = fd00::1/64
            ListenPort = 51820

            [Peer]
            PublicKey = $peerB64
            AllowedIPs = 10.99.0.2/32
        """.trimIndent()
        be.start(hostTunnel(configText = cfg).let {
            it.copy(hostMode = it.hostMode!!.copy(
                enrolledPeers = listOf(
                    EnrolledPeer(peerB64, "10.99.0.2", "g", 1L))
            ))
        })
        val (addr, _, _) = factory.opens.single()
        assertEquals("10.99.0.1,fd00::1", addr,
            "dual-stack Address lines must flow as comma-joined to the bridge factory")
    }

    @Test
    fun `V6_H1 comma-separated single-line dual-stack also flows correctly`() = runBlocking<Unit> {
        val backend = HookedBackend()
        val factory = HookedFactory { backend }
        val be = HostModeBackend(factory, parentScope)
        val cfg = """
            [Interface]
            PrivateKey = $privB64
            Address = 10.99.0.1/24, fd00::1/64
            ListenPort = 51820

            [Peer]
            PublicKey = $peerB64
            AllowedIPs = 10.99.0.2/32
        """.trimIndent()
        be.start(hostTunnel(configText = cfg).let {
            it.copy(hostMode = it.hostMode!!.copy(
                enrolledPeers = listOf(
                    EnrolledPeer(peerB64, "10.99.0.2", "g", 1L))
            ))
        })
        val (addr, _, _) = factory.opens.single()
        assertEquals("10.99.0.1,fd00::1", addr)
    }

    // ───────────────────── D4.H1 N-tunnel tests ─────────────────────

    @Test
    fun `two host tunnels with different ids run concurrently`() = runBlocking<Unit> {
        val factory = HookedFactory { HookedBackend() }
        val be = HostModeBackend(factory, parentScope)
        be.start(hostTunnel(id = "t1", listenPort = 51820))
        be.start(hostTunnel(id = "t2", listenPort = 51821))
        // Both tunnels opened fresh bridges (different ids never
        // share a slot, so no reuse).
        assertEquals(2, factory.opens.size)
        assertEquals(setOf("t1", "t2"), be.activeTunnelIds.value)
    }

    @Test
    fun `stop one tunnel leaves the other running`() = runBlocking<Unit> {
        val backends = mutableListOf<HookedBackend>()
        val factory = HookedFactory {
            HookedBackend().also { backends += it }
        }
        val be = HostModeBackend(factory, parentScope)
        be.start(hostTunnel(id = "t1", listenPort = 51820))
        be.start(hostTunnel(id = "t2", listenPort = 51821))
        be.stop("t1")
        assertEquals(setOf("t2"), be.activeTunnelIds.value)
        // t1's backend was paused, not closed.
        assertEquals(0, backends[0].closeCount.get(),
            "stop() pauses; the bridge must stay alive for resume")
        assertEquals(0, backends[1].closeCount.get())
    }

    @Test
    fun `teardown one tunnel leaves the other running`() = runBlocking<Unit> {
        val backends = mutableListOf<HookedBackend>()
        val factory = HookedFactory {
            HookedBackend().also { backends += it }
        }
        val be = HostModeBackend(factory, parentScope)
        be.start(hostTunnel(id = "t1", listenPort = 51820))
        be.start(hostTunnel(id = "t2", listenPort = 51821))
        be.teardown("t1")
        assertEquals(setOf("t2"), be.activeTunnelIds.value)
        // t1's backend was closed; t2's was not.
        assertEquals(1, backends[0].closeCount.get())
        assertEquals(0, backends[1].closeCount.get())
    }

    @Test
    fun `teardownAll closes every running tunnel`() = runBlocking<Unit> {
        val backends = mutableListOf<HookedBackend>()
        val factory = HookedFactory {
            HookedBackend().also { backends += it }
        }
        val be = HostModeBackend(factory, parentScope)
        be.start(hostTunnel(id = "t1", listenPort = 51820))
        be.start(hostTunnel(id = "t2", listenPort = 51821))
        be.teardownAll()
        assertEquals(1, backends[0].closeCount.get())
        assertEquals(1, backends[1].closeCount.get())
        assertTrue(be.activeTunnelIds.value.isEmpty())
    }

    @Test
    fun `start same id while already running is idempotent reconfigure`() = runBlocking<Unit> {
        val backend = HookedBackend()
        val factory = HookedFactory { backend }
        val be = HostModeBackend(factory, parentScope)
        be.start(hostTunnel(id = "t1"))
        be.start(hostTunnel(id = "t1"))
        // Only one bridge ever opened.
        assertEquals(1, factory.opens.size,
            "second start() with same id must not open a new bridge")
        // Two UAPI calls: initial start, reconfigure.
        assertEquals(2, backend.uapiCalls.size)
        assertEquals(setOf("t1"), be.activeTunnelIds.value)
    }

    @Test
    fun `snapshotStats per tunnel id returns the right backend's dump`() = runBlocking<Unit> {
        val pubB64a = Base64.getEncoder().encodeToString(ByteArray(32) { 1.toByte() })
        val pubB64b = Base64.getEncoder().encodeToString(ByteArray(32) { 2.toByte() })
        val backendA = HookedBackend(
            uapiDump = """
                listen_port=51820
                public_key=${"01".repeat(32)}
                last_handshake_time_sec=1000
                last_handshake_time_nsec=0
                tx_bytes=11
                rx_bytes=22
            """.trimIndent() + "\n"
        )
        val backendB = HookedBackend(
            uapiDump = """
                listen_port=51821
                public_key=${"02".repeat(32)}
                last_handshake_time_sec=3000
                last_handshake_time_nsec=0
                tx_bytes=33
                rx_bytes=44
            """.trimIndent() + "\n"
        )
        val backendsQueue = ArrayDeque<HookedBackend>().apply {
            addLast(backendA); addLast(backendB)
        }
        val factory = HookedFactory { backendsQueue.removeFirst() }
        val be = HostModeBackend(factory, parentScope)
        be.start(hostTunnel(id = "t1", listenPort = 51820))
        be.start(hostTunnel(id = "t2", listenPort = 51821))
        val statsA = be.snapshotStats("t1")!!
        val statsB = be.snapshotStats("t2")!!
        assertEquals(11L, statsA.totalTxBytes)
        assertEquals(22L, statsA.totalRxBytes)
        assertEquals(33L, statsB.totalTxBytes)
        assertEquals(44L, statsB.totalRxBytes)
        assertEquals(1_000_000L, statsA.peers[pubB64a]!!.lastHandshakeEpochMs)
        assertEquals(3_000_000L, statsB.peers[pubB64b]!!.lastHandshakeEpochMs)
    }

    @Test
    fun `snapshotAllStats returns map keyed by tunnel id`() = runBlocking<Unit> {
        val backendA = HookedBackend(
            uapiDump = """
                listen_port=51820
                public_key=${"01".repeat(32)}
                last_handshake_time_sec=1000
                last_handshake_time_nsec=0
                tx_bytes=11
                rx_bytes=22
            """.trimIndent() + "\n"
        )
        val backendB = HookedBackend(
            uapiDump = """
                listen_port=51821
                public_key=${"02".repeat(32)}
                last_handshake_time_sec=3000
                last_handshake_time_nsec=0
                tx_bytes=33
                rx_bytes=44
            """.trimIndent() + "\n"
        )
        val backendsQueue = ArrayDeque<HookedBackend>().apply {
            addLast(backendA); addLast(backendB)
        }
        val factory = HookedFactory { backendsQueue.removeFirst() }
        val be = HostModeBackend(factory, parentScope)
        be.start(hostTunnel(id = "t1", listenPort = 51820))
        be.start(hostTunnel(id = "t2", listenPort = 51821))
        val all = be.snapshotAllStats()
        assertEquals(setOf("t1", "t2"), all.keys)
        assertEquals(11L, all["t1"]!!.totalTxBytes)
        assertEquals(33L, all["t2"]!!.totalTxBytes)
    }

    @Test
    fun `activeTunnelIds flow emits on start stop teardown`() = runBlocking<Unit> {
        // Assert against the StateFlow directly via first { predicate }
        // rather than running a collector and reading a list — the
        // production code's withContext(Dispatchers.IO) breaks the
        // happens-before from the test-scheduler's yield(), so the
        // collector-based variant flakes under load (cf. FLAKE/#359).
        val be = HostModeBackend(HookedFactory { HookedBackend() }, parentScope)
        // Initial state: empty.
        assertEquals(emptySet<String>(), be.activeTunnelIds.value)
        // start → set containing t1.
        be.start(hostTunnel(id = "t1"))
        be.activeTunnelIds.first { it == setOf("t1") }
        // start t2 → set containing both.
        be.start(hostTunnel(id = "t2", listenPort = 51821))
        be.activeTunnelIds.first { it == setOf("t1", "t2") }
        // stop t1 → set with only t2.
        be.stop("t1")
        be.activeTunnelIds.first { it == setOf("t2") }
        // teardown t2 → empty.
        be.teardown("t2")
        be.activeTunnelIds.first { it.isEmpty() }
    }

    // ───────────────── D4.H4 port-collision guard ─────────────────

    @Test
    fun `start fails when another active tunnel already bound the listen port`() = runBlocking<Unit> {
        val factory = HookedFactory { HookedBackend() }
        val be = HostModeBackend(factory, parentScope)
        be.start(hostTunnel(id = "t1", listenPort = 51820))
        val ex = assertThrows(PortCollisionException::class.java) {
            runBlocking { be.start(hostTunnel(id = "t2", listenPort = 51820)) }
        }
        assertEquals("t2", ex.newTunnelId)
        assertEquals("t1", ex.existingTunnelId)
        assertEquals(51820, ex.port)
        // The second bridge must NOT have been opened.
        assertEquals(1, factory.opens.size)
        assertEquals(setOf("t1"), be.activeTunnelIds.value)
    }

    @Test
    fun `paused tunnel does not collide with a fresh start on the same port`() = runBlocking<Unit> {
        // Paused slots are bound to listen_port=0 — the kernel-level
        // conflict only fires once they resume, so a different tunnel
        // is free to claim the port in the meantime.
        val factory = HookedFactory { HookedBackend() }
        val be = HostModeBackend(factory, parentScope)
        be.start(hostTunnel(id = "t1", listenPort = 51820))
        be.stop("t1")
        be.start(hostTunnel(id = "t2", listenPort = 51820))
        assertEquals(setOf("t2"), be.activeTunnelIds.value)
        assertEquals(2, factory.opens.size)
    }

    @Test
    fun `resuming a paused tunnel fails when another tunnel grabbed its port`() = runBlocking<Unit> {
        val factory = HookedFactory { HookedBackend() }
        val be = HostModeBackend(factory, parentScope)
        be.start(hostTunnel(id = "t1", listenPort = 51820))
        be.stop("t1")
        // t2 takes over port 51820 while t1 was paused.
        be.start(hostTunnel(id = "t2", listenPort = 51820))
        // Now the user tries to resume t1 with its original port.
        val ex = assertThrows(PortCollisionException::class.java) {
            runBlocking { be.start(hostTunnel(id = "t1", listenPort = 51820)) }
        }
        assertEquals("t1", ex.newTunnelId)
        assertEquals("t2", ex.existingTunnelId)
        assertEquals(51820, ex.port)
        // t1 stays paused; t2 stays active.
        assertEquals(setOf("t2"), be.activeTunnelIds.value)
    }

    @Test
    fun `same-id reconfigure that does not change port stays valid`() = runBlocking<Unit> {
        val factory = HookedFactory { HookedBackend() }
        val be = HostModeBackend(factory, parentScope)
        be.start(hostTunnel(id = "t1", listenPort = 51820))
        // Starting the same id again is the idempotent-reconfigure
        // path; the collision check must not flag the slot against
        // itself.
        be.start(hostTunnel(id = "t1", listenPort = 51820))
        assertEquals(setOf("t1"), be.activeTunnelIds.value)
    }

    @Test
    fun `editing an active tunnel's port frees the original for another tunnel`() = runBlocking<Unit> {
        // After resume on a new ListenPort, the slot's recorded port
        // must follow — otherwise the old (stale) port stays in the
        // collision set and locks out other tunnels.
        val factory = HookedFactory { HookedBackend() }
        val be = HostModeBackend(factory, parentScope)
        be.start(hostTunnel(id = "t1", listenPort = 51820))
        be.stop("t1")
        // User edits t1's ListenPort to 51830 and resumes.
        be.start(hostTunnel(id = "t1", listenPort = 51830))
        // 51820 is now free; t2 should be able to claim it.
        be.start(hostTunnel(id = "t2", listenPort = 51820))
        assertEquals(setOf("t1", "t2"), be.activeTunnelIds.value)
    }

    @Test
    fun `two concurrent start calls for the same id only open one bridge`() = runTest {
        val sharedBackend = HookedBackend()
        val factory = HookedFactory { sharedBackend }
        val be = HostModeBackend(factory, backgroundScope)
        val t = hostTunnel(id = "race")
        // Fire two starts on independent dispatcher threads. The
        // HostModeBackend must serialize the cold-start race so we
        // end up with exactly one slot and one open() call.
        coroutineScope {
            launch(Dispatchers.IO) { be.start(t) }
            launch(Dispatchers.IO) { be.start(t) }
        }
        assertEquals(1, factory.opens.size,
            "concurrent same-id start must not open the bridge twice")
        assertEquals(setOf("race"), be.activeTunnelIds.value)
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

    /**
     * Factory that produces a fresh [WgBridgeBackend] per call,
     * picked by the supplier. Single-tunnel tests can pin the
     * supplier to a constant (`HookedFactory { sharedBackend }`);
     * multi-tunnel tests vary it per call so each slot can be
     * asserted independently.
     */
    private class HookedFactory(
        private val backendSupplier: () -> WgBridgeBackend,
    ) : WgBridgeBackendFactory {
        val opens = mutableListOf<Triple<String, Int, Int>>()
        override fun open(localAddr: String, mtu: Int, listenPort: Int): WgBridgeBackend {
            opens += Triple(localAddr, mtu, listenPort)
            return backendSupplier()
        }
    }
}
