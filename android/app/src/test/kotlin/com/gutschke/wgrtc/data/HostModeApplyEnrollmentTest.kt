package com.gutschke.wgrtc.data

import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.File
import java.nio.file.Path
import java.util.concurrent.atomic.AtomicReference

/**
 * Tests for the [applyEnrollmentToTunnel] helper used by
 * [HostModeDispatcher.applyEnrollment]. Verifies the persist-then-
 * reconfig sequencing in isolation from the WSS plumbing.
 */
class HostModeApplyEnrollmentTest {

    private val sampleInterface = """
        [Interface]
        PrivateKey = qFnYmBe2cGS9I9wCWC0Od4FquE1ToUJUVu/S35r443I=
        Address = 10.99.0.1/24
        ListenPort = 51820
    """.trimIndent()

    private fun store(dir: Path) = TunnelStore(File(dir.toFile(), "tunnels.json"))

    @Test fun `persists peer to tunnels json`(@TempDir dir: Path) = runBlocking {
        val s = store(dir)
        val t = Tunnel(
            id = "t1", name = "host", configText = sampleInterface,
            source = Tunnel.Source.HOST_MODE,
            hostMode = HostModeConfig(subnet = "10.99.0.0/24"),
        )
        s.save(listOf(t))
        applyEnrollmentToTunnel(
            store = s,
            tunnelId = "t1",
            peer = InboundEnrollHandler.NewPeer("pubA", "10.99.0.2", "alice"),
            nowMs = 1000L,
            reconfigurer = null,
        )
        val loaded = s.load()
        assertEquals(1, loaded.size)
        assertEquals(1, loaded[0].hostMode!!.enrolledPeers.size)
        val peer = loaded[0].hostMode!!.enrolledPeers[0]
        assertEquals("pubA", peer.pubkeyB64)
        assertEquals("10.99.0.2", peer.assignedIp)
        assertEquals("alice", peer.nameHint)
        assertEquals(1000L, peer.enrolledAtMs)
    }

    @Test fun `invokes reconfigurer with rendered config`(@TempDir dir: Path) = runBlocking {
        val s = store(dir)
        val t = Tunnel(
            id = "t1", name = "host", configText = sampleInterface,
            source = Tunnel.Source.HOST_MODE,
            hostMode = HostModeConfig(subnet = "10.99.0.0/24"),
        )
        s.save(listOf(t))
        val captured = AtomicReference<Pair<String, String>?>(null)
        val reconfigurer = object : HostModeReconfigurer {
            override suspend fun reconfigureHostTunnel(tunnelId: String, newConfigText: String) {
                captured.set(tunnelId to newConfigText)
            }
        }
        applyEnrollmentToTunnel(
            store = s, tunnelId = "t1",
            peer = InboundEnrollHandler.NewPeer("pubB", "10.99.0.3", "bob"),
            nowMs = 2000L, reconfigurer = reconfigurer,
        )
        val (id, cfg) = captured.get() ?: error("reconfigurer not called")
        assertEquals("t1", id)
        assertTrue(cfg.startsWith(sampleInterface),
            "rendered config must begin with [Interface]; got: $cfg")
        assertTrue(cfg.contains("[Peer]"))
        assertTrue(cfg.contains("PublicKey = pubB"))
        assertTrue(cfg.contains("AllowedIPs = 10.99.0.3/32"))
    }

    @Test fun `null reconfigurer just persists`(@TempDir dir: Path) = runBlocking {
        val s = store(dir)
        val t = Tunnel(
            id = "t1", name = "host", configText = sampleInterface,
            source = Tunnel.Source.HOST_MODE,
            hostMode = HostModeConfig(subnet = "10.99.0.0/24"),
        )
        s.save(listOf(t))
        // Should NOT throw despite reconfigurer = null.
        applyEnrollmentToTunnel(
            store = s, tunnelId = "t1",
            peer = InboundEnrollHandler.NewPeer("pubA", "10.99.0.2", "n"),
            nowMs = 1L, reconfigurer = null,
        )
        assertEquals(1, s.load()[0].hostMode!!.enrolledPeers.size)
    }

    @Test fun `unknown tunnel id is a no-op`(@TempDir dir: Path) = runBlocking {
        val s = store(dir)
        // Empty store.
        applyEnrollmentToTunnel(
            store = s, tunnelId = "missing",
            peer = InboundEnrollHandler.NewPeer("p", "10.0.0.2", "n"),
            nowMs = 1L, reconfigurer = null,
        )
        assertTrue(s.load().isEmpty())
    }

    @Test fun `non-host-mode tunnel triggers throws via withEnrolledPeer`(@TempDir dir: Path) = runBlocking {
        val s = store(dir)
        // Saving a client tunnel.
        val client = Tunnel(
            id = "c", name = "client", configText = "[Interface]\n",
            source = Tunnel.Source.LEGACY, hostMode = null,
        )
        s.save(listOf(client))
        // Programmer error: shouldn't be calling apply on a client.
        assertThrows(IllegalStateException::class.java) {
            runBlocking {
                applyEnrollmentToTunnel(
                    store = s, tunnelId = "c",
                    peer = InboundEnrollHandler.NewPeer("p", "10.0.0.2", "n"),
                    nowMs = 1L, reconfigurer = null,
                )
            }
        }
    }

    @Test fun `duplicate pubkey throws (caller must dedupe via allocator)`(@TempDir dir: Path) = runBlocking {
        val s = store(dir)
        val t = Tunnel(
            id = "t1", name = "h", configText = sampleInterface,
            source = Tunnel.Source.HOST_MODE,
            hostMode = HostModeConfig(
                subnet = "10.99.0.0/24",
                enrolledPeers = listOf(EnrolledPeer("pubA", "10.99.0.2", "first", 1L)),
            ),
        )
        s.save(listOf(t))
        assertThrows(IllegalStateException::class.java) {
            runBlocking {
                applyEnrollmentToTunnel(
                    store = s, tunnelId = "t1",
                    peer = InboundEnrollHandler.NewPeer("pubA", "10.99.0.3", "dup"),
                    nowMs = 2L, reconfigurer = null,
                )
            }
        }
        // Original state preserved.
        assertEquals(1, s.load()[0].hostMode!!.enrolledPeers.size)
    }

    @Test fun `reconfigurer failure does not roll back persistence`(@TempDir dir: Path) = runBlocking {
        // Document the contract: the persist happens BEFORE the reconfig.
        // If the reconfig throws, the store has already been written.
        // The caller (HostModeDispatcher) translates this into "swallow
        // OK response, force client retry".
        val s = store(dir)
        val t = Tunnel(
            id = "t1", name = "h", configText = sampleInterface,
            source = Tunnel.Source.HOST_MODE,
            hostMode = HostModeConfig(subnet = "10.99.0.0/24"),
        )
        s.save(listOf(t))
        val reconfigurer = object : HostModeReconfigurer {
            override suspend fun reconfigureHostTunnel(tunnelId: String, newConfigText: String) {
                throw RuntimeException("wg-go down")
            }
        }
        assertThrows(RuntimeException::class.java) {
            runBlocking {
                applyEnrollmentToTunnel(
                    store = s, tunnelId = "t1",
                    peer = InboundEnrollHandler.NewPeer("pubA", "10.99.0.2", "n"),
                    nowMs = 1L, reconfigurer = reconfigurer,
                )
            }
        }
        // Persistence happened.
        assertEquals(1, s.load()[0].hostMode!!.enrolledPeers.size)
    }
}
