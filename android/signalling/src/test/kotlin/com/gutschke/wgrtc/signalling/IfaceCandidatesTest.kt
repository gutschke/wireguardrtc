package com.gutschke.wgrtc.signalling

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

/**
 * Unit tests for the iface-candidate classifier. We intentionally
 * mirror the daemon's classification rules from `_classify_iface_addr`
 * in `github/wireguardrtc` so a host (Android phone) advertises
 * the same shapes of candidates the client side already knows how to
 * rank.
 */
class IfaceCandidatesTest {

    @Test fun `loopback v4 is ineligible`() {
        assertFalse(isCandidateEligibleV4("127.0.0.1"))
        assertFalse(isCandidateEligibleV4("127.255.255.254"))
    }

    @Test fun `link-local v4 is ineligible`() {
        assertFalse(isCandidateEligibleV4("169.254.1.5"))
        assertFalse(isCandidateEligibleV4("169.254.169.254"))
    }

    @Test fun `multicast v4 is ineligible`() {
        assertFalse(isCandidateEligibleV4("224.0.0.1"))
        assertFalse(isCandidateEligibleV4("239.255.255.255"))
    }

    @Test fun `unspecified is ineligible`() {
        assertFalse(isCandidateEligibleV4("0.0.0.0"))
    }

    @Test fun `RFC 7335 CLAT stub is ineligible`() {
        assertFalse(isCandidateEligibleV4("192.0.0.1"))
        assertFalse(isCandidateEligibleV4("192.0.0.7"))
        // Just outside the /29 — eligible.
        assertTrue(isCandidateEligibleV4("192.0.0.8"))
    }

    @Test fun `RFC 1918 ranges are private`() {
        assertTrue(isPrivateV4("10.0.0.1"))
        assertTrue(isPrivateV4("10.255.255.254"))
        assertTrue(isPrivateV4("172.16.0.1"))
        assertTrue(isPrivateV4("172.31.255.254"))
        assertTrue(isPrivateV4("192.168.1.1"))
        assertTrue(isPrivateV4("192.168.43.1")) // android tethering default
        assertTrue(isPrivateV4("192.168.49.1")) // alternate hotspot range
    }

    @Test fun `CGNAT range 100_64 _10 counts as private for ranking`() {
        // Field reality: many cellular CGNAT deployments are
        // hole-punchable, so we don't drop them — kind=lan, rank=50.
        assertTrue(isPrivateV4("100.64.0.1"))
        assertTrue(isPrivateV4("100.127.255.254"))
    }

    @Test fun `globally-routable v4 is not private`() {
        assertFalse(isPrivateV4("8.8.8.8"))
        assertFalse(isPrivateV4("203.0.113.5"))
    }

    @Test fun `tunnel iface names recognised`() {
        assertTrue(isTunnelIfaceName("wg0"))
        assertTrue(isTunnelIfaceName("wg0p1"))
        assertTrue(isTunnelIfaceName("tun0"))
        assertTrue(isTunnelIfaceName("tun7"))
        assertFalse(isTunnelIfaceName("eth0"))
        assertFalse(isTunnelIfaceName("wlan0"))
        assertFalse(isTunnelIfaceName("ap0"))
    }

    @Test fun `bridge iface names recognised`() {
        assertTrue(isBridgeIfaceName("br0"))
        assertTrue(isBridgeIfaceName("br-ec1234"))
        assertTrue(isBridgeIfaceName("docker0"))
        assertTrue(isBridgeIfaceName("vmbr0"))
        assertFalse(isBridgeIfaceName("eth0"))
        assertFalse(isBridgeIfaceName("wlan0"))
    }

    @Test fun `classify private wifi iface as lan rank 50`() {
        val cls = classifyIfaceAddr(
            iface = "wlan0", ip = "192.168.1.42",
            defaultIface = "wlan0", advertise = emptySet(),
            suppress = emptySet(), ownWg = emptySet(),
        )
        assertEquals(50 to "lan", cls)
    }

    @Test fun `classify hotspot ap iface as lan rank 50`() {
        // The hotspot AP iface name is policy-dependent (wlan2 on
        // Android phone, swlan0 on some Samsung) — we discriminate by
        // ADDRESS, not name. 192.168.43.1 = android tethering.
        val cls = classifyIfaceAddr(
            iface = "wlan2", ip = "192.168.43.1",
            defaultIface = "wlan0", advertise = emptySet(),
            suppress = emptySet(), ownWg = emptySet(),
        )
        assertEquals(50 to "lan", cls)
    }

    @Test fun `classify CGNAT cellular iface as lan rank 50`() {
        val cls = classifyIfaceAddr(
            iface = "rmnet0", ip = "100.65.42.7",
            defaultIface = "rmnet0", advertise = emptySet(),
            suppress = emptySet(), ownWg = emptySet(),
        )
        assertEquals(50 to "lan", cls)
    }

    @Test fun `classify docker bridge as lan rank 40`() {
        val cls = classifyIfaceAddr(
            iface = "docker0", ip = "172.17.0.1",
            defaultIface = "eth0", advertise = emptySet(),
            suppress = emptySet(), ownWg = emptySet(),
        )
        assertEquals(40 to "lan", cls)
    }

    @Test fun `classify globally-routable on default iface as stun rank 20`() {
        val cls = classifyIfaceAddr(
            iface = "eth0", ip = "203.0.113.5",
            defaultIface = "eth0", advertise = emptySet(),
            suppress = emptySet(), ownWg = emptySet(),
        )
        assertEquals(20 to "stun", cls)
    }

    @Test fun `classify globally-routable on non-default as stun rank 30`() {
        val cls = classifyIfaceAddr(
            iface = "eth1", ip = "192.0.2.1",
            defaultIface = "eth0", advertise = emptySet(),
            suppress = emptySet(), ownWg = emptySet(),
        )
        assertEquals(30 to "stun", cls)
    }

    @Test fun `advertise allowlist forces mesh rank 60 even on weird ips`() {
        // The user explicitly opts a particular iface into
        // advertising; respect it even if its IP would normally be
        // dropped (e.g. the iface itself is mostly link-local with
        // a single private addr). Note: ineligible IPs are still
        // dropped by `is_eligible`; advertise overrides ranking, not
        // eligibility.
        val cls = classifyIfaceAddr(
            iface = "wg-mesh", ip = "192.168.7.1",
            defaultIface = "eth0", advertise = setOf("wg-mesh"),
            suppress = emptySet(), ownWg = emptySet(),
        )
        assertEquals(60 to "mesh", cls)
    }

    @Test fun `own WG iface is dropped`() {
        val cls = classifyIfaceAddr(
            iface = "wg0", ip = "10.99.0.2",
            defaultIface = "eth0", advertise = emptySet(),
            suppress = emptySet(), ownWg = setOf("wg0"),
        )
        assertNull(cls)
    }

    @Test fun `suppress set wins`() {
        val cls = classifyIfaceAddr(
            iface = "eth1", ip = "192.168.50.1",
            defaultIface = "eth0", advertise = emptySet(),
            suppress = setOf("eth1"), ownWg = emptySet(),
        )
        assertNull(cls)
    }

    @Test fun `ineligible ip is dropped regardless of iface`() {
        val cls = classifyIfaceAddr(
            iface = "eth0", ip = "169.254.1.5",
            defaultIface = "eth0", advertise = emptySet(),
            suppress = emptySet(), ownWg = emptySet(),
        )
        assertNull(cls)
    }

    @Test fun `tunnel iface is dropped unless advertised`() {
        val cls = classifyIfaceAddr(
            iface = "tun0", ip = "10.7.0.1",
            defaultIface = "eth0", advertise = emptySet(),
            suppress = emptySet(), ownWg = emptySet(),
        )
        assertNull(cls)
    }

    @Test fun `tunnel iface kept when in advertise set`() {
        val cls = classifyIfaceAddr(
            iface = "tun0", ip = "10.7.0.1",
            defaultIface = "eth0", advertise = setOf("tun0"),
            suppress = emptySet(), ownWg = emptySet(),
        )
        assertEquals(60 to "mesh", cls)
    }

    @Test fun `enumerate via fake provider, dedupe by IP, sort by rank`() {
        val provider = FakeIfaceProvider(listOf(
            "wlan0" to "192.168.1.42", // lan, 50
            "rmnet0" to "100.66.7.1", // cgnat → lan, 50 (insertion order tiebreak)
            "eth0" to "203.0.113.5", // stun (default iface), 20
            "wlan0" to "192.168.1.42", // dup — drop
            "tun0" to "10.7.0.1", // tunnel, dropped
            "wg0" to "10.99.0.2", // own-wg, dropped
            "lo" to "127.0.0.1", // ineligible
        ))
        val out = enumerateAndRank(
            provider = provider,
            defaultIface = "eth0",
            advertise = emptySet(),
            suppress = emptySet(),
            ownWg = setOf("wg0"),
        )
        // Expect rank order 20 < 50 < 50.
        assertEquals(3, out.size)
        assertEquals("eth0" to "203.0.113.5", out[0].iface to out[0].ip)
        assertEquals("stun", out[0].kind)
        assertEquals(20, out[0].rank)
        assertEquals("lan", out[1].kind)
        assertEquals("lan", out[2].kind)
        // Rank-50 group order is insertion-stable.
        assertEquals("wlan0" to "192.168.1.42", out[1].iface to out[1].ip)
        assertEquals("rmnet0" to "100.66.7.1", out[2].iface to out[2].ip)
    }

    @Test fun `hotspot host scenario`() {
        // Realistic Android phone with hotspot active:
        // wlan0 = client wifi (off in this scenario)
        // wlan2 = hotspot AP, 192.168.43.1
        // rmnet_data0 = cellular, CGNAT 100.64.x.x
        // We want the hotspot LAN address to come out as a lan
        // candidate (rank 50) so guests can reach the phone over
        // the hotspot LAN; we also want the cellular CGNAT to come
        // out as a fallback.
        val provider = FakeIfaceProvider(listOf(
            "wlan2" to "192.168.43.1",
            "rmnet_data0" to "100.64.7.42",
        ))
        val out = enumerateAndRank(
            provider = provider,
            defaultIface = "rmnet_data0",
            advertise = emptySet(),
            suppress = emptySet(),
            ownWg = emptySet(),
        )
        assertEquals(2, out.size)
        // Both rank 50 (LAN), insertion order preserved → wlan2 first.
        assertTrue(out.all { it.rank == 50 && it.kind == "lan" })
        assertEquals("wlan2" to "192.168.43.1", out[0].iface to out[0].ip)
        assertEquals("rmnet_data0" to "100.64.7.42", out[1].iface to out[1].ip)
    }
}

private class FakeIfaceProvider(
    private val addrs: List<Pair<String, String>>,
) : IfaceAddrProvider {
    override fun list(): List<Pair<String, String>> = addrs
}
