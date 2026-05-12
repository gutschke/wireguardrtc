package com.gutschke.wgrtc.data

import kotlinx.serialization.json.Json
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.File
import java.nio.file.Path

/**
 * Tests for the host-mode extensions to [Tunnel] +
 * [TunnelStore]:
 *
 * - new `Source.HOST_MODE` enum value
 * - new `hostMode: HostModeConfig?` field carrying subnet + the
 * canonical list of enrolled peers
 * - render helpers that combine the host's `[Interface]` block with
 * the per-peer `[Peer]` blocks for wg-go consumption
 * - allocated-IP extraction for [HostSubnetAllocator]
 * - backwards-compat: existing tunnels.json files (no `hostMode`
 * field) still parse correctly with `hostMode = null`
 */
class HostModeTest {

    private val json = Json { prettyPrint = true; ignoreUnknownKeys = true }

    private val sampleInterface = """
        [Interface]
        PrivateKey = qFnYmBe2cGS9I9wCWC0Od4FquE1ToUJUVu/S35r443I=
        Address = 10.99.0.1/24
        ListenPort = 51820
    """.trimIndent()

    // ─── Data-model serialization ─────────────────────────────────────

    @Test fun `client tunnel serializes without hostMode field`() {
        val t = Tunnel(name = "client-1", configText = "[Interface]\nKey=X\n")
        val text = json.encodeToString(Tunnel.serializer(), t)
        // hostMode is null; serializer encodes it as null (or omits with
        // explicitNulls=false; default is to include).
        // Round-trip is the load-bearing assertion.
        val back = json.decodeFromString(Tunnel.serializer(), text)
        assertEquals(t, back)
        assertNull(back.hostMode)
    }

    @Test fun `host-mode tunnel round-trips`() {
        val t = Tunnel(
            name = "host",
            configText = sampleInterface,
            source = Tunnel.Source.HOST_MODE,
            hostMode = HostModeConfig(
                subnet = "10.99.0.0/24",
                enrolledPeers = listOf(
                    EnrolledPeer(
                        pubkeyB64 = "/SrxCmYs3WeSu/lJCYs+CQFe0mSZ0bVbAgTXTbfR7hc=",
                        assignedIp = "10.99.0.2",
                        nameHint = "alice",
                        enrolledAtMs = 1_700_000_000_000L,
                    ),
                ),
            ),
        )
        val text = json.encodeToString(Tunnel.serializer(), t)
        val back = json.decodeFromString(Tunnel.serializer(), text)
        assertEquals(t, back)
        assertEquals(Tunnel.Source.HOST_MODE, back.source)
        assertEquals("10.99.0.0/24", back.hostMode!!.subnet)
        assertEquals(1, back.hostMode!!.enrolledPeers.size)
    }

    @Test fun `legacy tunnels json without hostMode field still loads`() {
        // Simulate a tunnels.json from before host-mode shipped.
        val legacy = """
            {
              "id": "abc-123",
              "name": "legacy",
              "configText": "[Interface]\nKey=X\n",
              "source": "LEGACY"
            }
        """.trimIndent()
        val t = json.decodeFromString(Tunnel.serializer(), legacy)
        assertEquals("legacy", t.name)
        assertNull(t.hostMode)
        assertEquals(Tunnel.Source.LEGACY, t.source)
    }

    // ─── Render helpers ───────────────────────────────────────────────

    @Test fun `client tunnel render returns configText verbatim`() {
        val t = Tunnel(name = "c", configText = sampleInterface, source = Tunnel.Source.LEGACY)
        assertEquals(sampleInterface, renderWgConfig(t))
    }

    @Test fun `host-mode tunnel render appends peer blocks`() {
        val t = Tunnel(
            name = "host",
            configText = sampleInterface,
            source = Tunnel.Source.HOST_MODE,
            hostMode = HostModeConfig(
                subnet = "10.99.0.0/24",
                enrolledPeers = listOf(
                    EnrolledPeer(
                        pubkeyB64 = "/SrxCmYs3WeSu/lJCYs+CQFe0mSZ0bVbAgTXTbfR7hc=",
                        assignedIp = "10.99.0.2",
                        nameHint = "alice",
                        enrolledAtMs = 1L,
                    ),
                    EnrolledPeer(
                        pubkeyB64 = "K8lFOOKlPCCB0R8bUmxpkRPN+N5X79eR+oL7+lhV2mY=",
                        assignedIp = "10.99.0.3",
                        nameHint = "bob",
                        enrolledAtMs = 2L,
                    ),
                ),
            ),
        )
        val rendered = renderWgConfig(t)
        // Must start with the host's [Interface] block.
        assertTrue(rendered.startsWith(sampleInterface),
            "rendered config must begin with the [Interface] block; got: $rendered")
        // Each peer must appear as a [Peer] block with PublicKey + AllowedIPs.
        assertTrue(rendered.contains("[Peer]"))
        assertTrue(rendered.contains(
            "PublicKey = /SrxCmYs3WeSu/lJCYs+CQFe0mSZ0bVbAgTXTbfR7hc="))
        assertTrue(rendered.contains("AllowedIPs = 10.99.0.2/32"))
        assertTrue(rendered.contains(
            "PublicKey = K8lFOOKlPCCB0R8bUmxpkRPN+N5X79eR+oL7+lhV2mY="))
        assertTrue(rendered.contains("AllowedIPs = 10.99.0.3/32"))
        // Sanity: there are TWO [Peer] blocks.
        assertEquals(2, rendered.split("[Peer]").size - 1)
    }

    @Test fun `host-mode with no peers renders just the interface block`() {
        val t = Tunnel(
            name = "host-empty",
            configText = sampleInterface,
            source = Tunnel.Source.HOST_MODE,
            hostMode = HostModeConfig(subnet = "10.99.0.0/24"),
        )
        val rendered = renderWgConfig(t)
        assertEquals(sampleInterface, rendered)
        assertFalse(rendered.contains("[Peer]"))
    }

    // ─── Allocation helpers ───────────────────────────────────────────

    @Test fun `allocatedIps for host-mode returns peer ips`() {
        val t = Tunnel(
            name = "x",
            configText = sampleInterface,
            source = Tunnel.Source.HOST_MODE,
            hostMode = HostModeConfig(
                subnet = "10.99.0.0/24",
                enrolledPeers = listOf(
                    EnrolledPeer("p1", "10.99.0.2", "a", 1L),
                    EnrolledPeer("p2", "10.99.0.4", "b", 2L),
                ),
            ),
        )
        assertEquals(setOf("10.99.0.2", "10.99.0.4"), allocatedIps(t))
    }

    @Test fun `allocatedIps for client tunnel is empty`() {
        val t = Tunnel(name = "c", configText = sampleInterface)
        assertEquals(emptySet<String>(), allocatedIps(t))
    }

    @Test fun `allocatedIps for host-mode with no peers is empty`() {
        val t = Tunnel(
            name = "x", configText = sampleInterface,
            source = Tunnel.Source.HOST_MODE,
            hostMode = HostModeConfig(subnet = "10.99.0.0/24"),
        )
        assertEquals(emptySet<String>(), allocatedIps(t))
    }

    // ─── Mutation helpers ────────────────────────────────────────────

    @Test fun `withEnrolledPeer appends to the list`() {
        val t = Tunnel(
            name = "x", configText = sampleInterface,
            source = Tunnel.Source.HOST_MODE,
            hostMode = HostModeConfig(subnet = "10.99.0.0/24"),
        )
        val updated = t.withEnrolledPeer(
            EnrolledPeer("p1", "10.99.0.2", "alice", 100L),
        )
        assertEquals(1, updated.hostMode!!.enrolledPeers.size)
        assertEquals("alice", updated.hostMode!!.enrolledPeers[0].nameHint)
        // Original is unchanged (data classes are immutable).
        assertEquals(0, t.hostMode!!.enrolledPeers.size)
    }

    @Test fun `withEnrolledPeer on a non-host-mode tunnel throws`() {
        val t = Tunnel(name = "client", configText = sampleInterface)
        assertThrows(IllegalStateException::class.java) {
            t.withEnrolledPeer(EnrolledPeer("p", "10.0.0.2", "n", 1L))
        }
    }

    @Test fun `withEnrolledPeer rejects duplicate pubkey`() {
        val t = Tunnel(
            name = "x", configText = sampleInterface,
            source = Tunnel.Source.HOST_MODE,
            hostMode = HostModeConfig(
                subnet = "10.99.0.0/24",
                enrolledPeers = listOf(EnrolledPeer("p", "10.99.0.2", "a", 1L)),
            ),
        )
        assertThrows(IllegalStateException::class.java) {
            t.withEnrolledPeer(EnrolledPeer("p", "10.99.0.3", "a-dup", 2L))
        }
    }

    @Test fun `withEnrolledPeer rejects duplicate ip`() {
        val t = Tunnel(
            name = "x", configText = sampleInterface,
            source = Tunnel.Source.HOST_MODE,
            hostMode = HostModeConfig(
                subnet = "10.99.0.0/24",
                enrolledPeers = listOf(EnrolledPeer("pA", "10.99.0.2", "a", 1L)),
            ),
        )
        assertThrows(IllegalStateException::class.java) {
            t.withEnrolledPeer(EnrolledPeer("pB", "10.99.0.2", "b", 2L))
        }
    }

    @Test fun `withoutEnrolledPeer removes by pubkey`() {
        val t = Tunnel(
            name = "x", configText = sampleInterface,
            source = Tunnel.Source.HOST_MODE,
            hostMode = HostModeConfig(
                subnet = "10.99.0.0/24",
                enrolledPeers = listOf(
                    EnrolledPeer("p1", "10.99.0.2", "a", 1L),
                    EnrolledPeer("p2", "10.99.0.3", "b", 2L),
                ),
            ),
        )
        val updated = t.withoutEnrolledPeer("p1")
        assertEquals(1, updated.hostMode!!.enrolledPeers.size)
        assertEquals("p2", updated.hostMode!!.enrolledPeers[0].pubkeyB64)
    }

    @Test fun `withoutEnrolledPeer on unknown pubkey is a no-op`() {
        val t = Tunnel(
            name = "x", configText = sampleInterface,
            source = Tunnel.Source.HOST_MODE,
            hostMode = HostModeConfig(
                subnet = "10.99.0.0/24",
                enrolledPeers = listOf(EnrolledPeer("p1", "10.99.0.2", "a", 1L)),
            ),
        )
        val updated = t.withoutEnrolledPeer("not-a-real-pubkey")
        assertEquals(t, updated)
    }

    // ─── Persistence round-trip ───────────────────────────────────────

    @Test fun `TunnelStore round-trips a host-mode tunnel`(@TempDir dir: Path) {
        val store = TunnelStore(File(dir.toFile(), "tunnels.json"))
        val t = Tunnel(
            name = "host-x",
            configText = sampleInterface,
            source = Tunnel.Source.HOST_MODE,
            hostMode = HostModeConfig(
                subnet = "10.99.0.0/24",
                enrolledPeers = listOf(
                    EnrolledPeer("p", "10.99.0.5", "alice", 999L),
                ),
            ),
        )
        store.save(listOf(t))
        val loaded = store.load()
        assertEquals(1, loaded.size)
        assertEquals(t, loaded[0])
    }

    @Test fun `TunnelStore loads mixed client + host-mode tunnels`(@TempDir dir: Path) {
        val store = TunnelStore(File(dir.toFile(), "tunnels.json"))
        val client = Tunnel(name = "c", configText = "[Interface]\n", source = Tunnel.Source.ENROLL)
        val host = Tunnel(
            name = "h", configText = sampleInterface,
            source = Tunnel.Source.HOST_MODE,
            hostMode = HostModeConfig("10.99.0.0/24"),
        )
        store.save(listOf(client, host))
        val loaded = store.load()
        assertEquals(listOf(client, host), loaded)
    }
}
