package com.gutschke.wgrtc.signalling

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

/**
 * Pure-JVM tests for the CIDR utility used by the bootstrap-deadlock
 * check (Step A) and the same-subnet override (Step D). Boundaries
 * matter: an off-by-one in `cidrContains` shows up as either a
 * false-rejected legitimate candidate or a false-accepted
 * deadlock-trigger, so we exercise the prefix lengths that show up
 * in real configs.
 */
class CidrTest {

    // ─── parseCidr ────────────────────────────────────────────────────

    @Test fun `parseCidr accepts dotted-quad with prefix`() {
        val (b, p) = parseCidr("10.0.0.0/24")!!
        assertEquals(24, p)
        assertArrayEquals(byteArrayOf(10, 0, 0, 0), b)
    }

    @Test fun `parseCidr accepts bare IPv4 as a 32 host route`() {
        val (b, p) = parseCidr("1.2.3.4")!!
        assertEquals(32, p)
        assertArrayEquals(byteArrayOf(1, 2, 3, 4), b)
    }

    @Test fun `parseCidr accepts bare IPv6 as a 128 host route`() {
        val (_, p) = parseCidr("::1")!!
        assertEquals(128, p)
    }

    @Test fun `parseCidr rejects negative prefix`() {
        assertNull(parseCidr("10.0.0.0/-1"))
    }

    @Test fun `parseCidr rejects oversize prefix`() {
        assertNull(parseCidr("10.0.0.0/33"))
    }

    @Test fun `parseCidr rejects garbage`() {
        assertNull(parseCidr("not-an-ip/24"))
        assertNull(parseCidr(""))
        assertNull(parseCidr("/"))
        assertNull(parseCidr("10.0.0.0/abc"))
    }

    // ─── cidrContains: IPv4 boundaries ────────────────────────────────

    private fun bytes(a: Int, b: Int, c: Int, d: Int) =
        byteArrayOf(a.toByte(), b.toByte(), c.toByte(), d.toByte())

    @Test fun `slash 0 contains anything v4`() {
        val net = bytes(0, 0, 0, 0)
        assertTrue(cidrContains(net, 0, bytes(1, 2, 3, 4)))
        assertTrue(cidrContains(net, 0, bytes(255, 255, 255, 255)))
    }

    @Test fun `slash 32 is a single host`() {
        val net = bytes(192, 168, 1, 5)
        assertTrue(cidrContains(net, 32, bytes(192, 168, 1, 5)))
        assertFalse(cidrContains(net, 32, bytes(192, 168, 1, 6)))
    }

    @Test fun `slash 24 boundaries`() {
        val net = bytes(10, 0, 0, 0)
        assertTrue(cidrContains(net, 24, bytes(10, 0, 0, 0)))
        assertTrue(cidrContains(net, 24, bytes(10, 0, 0, 255)))
        assertFalse(cidrContains(net, 24, bytes(10, 0, 1, 0)))
        assertFalse(cidrContains(net, 24, bytes(11, 0, 0, 0)))
    }

    @Test fun `slash 16 boundaries`() {
        val net = bytes(192, 168, 0, 0)
        assertTrue(cidrContains(net, 16, bytes(192, 168, 0, 1)))
        assertTrue(cidrContains(net, 16, bytes(192, 168, 255, 254)))
        assertFalse(cidrContains(net, 16, bytes(192, 169, 0, 1)))
        assertFalse(cidrContains(net, 16, bytes(193, 168, 0, 1)))
    }

    @Test fun `slash 8 boundaries`() {
        val net = bytes(10, 0, 0, 0)
        assertTrue(cidrContains(net, 8, bytes(10, 99, 5, 1)))
        assertTrue(cidrContains(net, 8, bytes(10, 0, 0, 0)))
        assertFalse(cidrContains(net, 8, bytes(11, 0, 0, 0)))
        assertFalse(cidrContains(net, 8, bytes(9, 255, 255, 255)))
    }

    @Test fun `partial bit prefix slash 22`() {
        // 10.0.0.0/22 covers 10.0.0.0 through 10.0.3.255.
        val net = bytes(10, 0, 0, 0)
        assertTrue(cidrContains(net, 22, bytes(10, 0, 0, 0)))
        assertTrue(cidrContains(net, 22, bytes(10, 0, 3, 255)))
        assertFalse(cidrContains(net, 22, bytes(10, 0, 4, 0)))
    }

    @Test fun `mismatched address families return false`() {
        // v4 net, v6 candidate — different array sizes.
        val v4 = bytes(10, 0, 0, 0)
        val v6 = ByteArray(16)
        assertFalse(cidrContains(v4, 24, v6))
    }

    // ─── isInAnyCidr ──────────────────────────────────────────────────

    @Test fun `isInAnyCidr with empty list returns false`() {
        assertFalse(isInAnyCidr("1.2.3.4", emptyList()))
    }

    @Test fun `isInAnyCidr matches a single CIDR`() {
        assertTrue(isInAnyCidr("10.0.0.5", listOf("10.0.0.0/24")))
        assertFalse(isInAnyCidr("10.0.1.5", listOf("10.0.0.0/24")))
    }

    @Test fun `isInAnyCidr matches any of multiple CIDRs`() {
        val list = listOf("10.0.0.0/24", "192.168.0.0/16")
        assertTrue(isInAnyCidr("10.0.0.5", list))
        assertTrue(isInAnyCidr("192.168.42.1", list))
        assertFalse(isInAnyCidr("203.0.113.1", list))
    }

    @Test fun `isInAnyCidr with 0_0_0_0 0 catches everything`() {
        assertTrue(isInAnyCidr("203.0.113.1", listOf("0.0.0.0/0")))
        assertTrue(isInAnyCidr("10.0.0.1", listOf("0.0.0.0/0")))
    }

    @Test fun `isInAnyCidr silently skips malformed entries`() {
        // Garbage shouldn't disable the rest of the list.
        val list = listOf("not-a-cidr", "10.0.0.0/24")
        assertTrue(isInAnyCidr("10.0.0.5", list))
    }

    @Test fun `isInAnyCidr with non-IP candidate returns false`() {
        assertFalse(isInAnyCidr("not-an-ip", listOf("0.0.0.0/0")))
    }

    @Test fun `isInAnyCidr does not cross address families`() {
        // v6 candidate, v4 list — should NOT match 0.0.0.0/0.
        assertFalse(isInAnyCidr("::1", listOf("0.0.0.0/0")))
    }

    // ─── parseAllowedIps ──────────────────────────────────────────────

    @Test fun `parseAllowedIps reads single line CSV`() {
        val cfg = """
            [Interface]
            PrivateKey = AAA
            [Peer]
            PublicKey = BBB
            AllowedIPs = 10.0.0.0/24, 192.168.0.0/16
        """.trimIndent()
        assertEquals(listOf("10.0.0.0/24", "192.168.0.0/16"), parseAllowedIps(cfg))
    }

    @Test fun `parseAllowedIps unions multiple AllowedIPs lines`() {
        val cfg = """
            [Peer]
            AllowedIPs = 10.0.0.0/24
            AllowedIPs = 192.168.0.0/16
        """.trimIndent()
        assertEquals(listOf("10.0.0.0/24", "192.168.0.0/16"), parseAllowedIps(cfg))
    }

    @Test fun `parseAllowedIps normalises bare IPs`() {
        val cfg = "AllowedIPs = 1.2.3.4, ::1"
        assertEquals(listOf("1.2.3.4/32", "::1/128"), parseAllowedIps(cfg))
    }

    @Test fun `parseAllowedIps handles 0_0_0_0 0 catchall`() {
        val cfg = "AllowedIPs = 0.0.0.0/0"
        assertEquals(listOf("0.0.0.0/0"), parseAllowedIps(cfg))
    }

    @Test fun `parseAllowedIps is case-insensitive on key`() {
        val cfg = "allowedips = 10.0.0.0/24"
        assertEquals(listOf("10.0.0.0/24"), parseAllowedIps(cfg))
    }

    @Test fun `parseAllowedIps drops malformed entries silently`() {
        val cfg = "AllowedIPs = 10.0.0.0/24, not-a-cidr, 192.168.0.0/16"
        assertEquals(
            listOf("10.0.0.0/24", "192.168.0.0/16"),
            parseAllowedIps(cfg)
        )
    }

    @Test fun `parseAllowedIps on config without AllowedIPs returns empty`() {
        val cfg = "[Interface]\nPrivateKey = AAA\n[Peer]\nPublicKey = BBB\n"
        assertTrue(parseAllowedIps(cfg).isEmpty())
    }

    @Test fun `parseAllowedIps tolerates whitespace and empty entries`() {
        val cfg = "AllowedIPs = 10.0.0.0/24 , , , 192.168.0.0/16 "
        assertEquals(
            listOf("10.0.0.0/24", "192.168.0.0/16"),
            parseAllowedIps(cfg)
        )
    }

    // ─── cidrsOverlap ─────────────────────────────────────────────────

    @Test fun `cidrsOverlap empty lists return false`() {
        assertFalse(cidrsOverlap(emptyList(), listOf("10.0.0.0/24")))
        assertFalse(cidrsOverlap(listOf("10.0.0.0/24"), emptyList()))
        assertFalse(cidrsOverlap(emptyList(), emptyList()))
    }

    @Test fun `cidrsOverlap identical CIDRs overlap`() {
        assertTrue(cidrsOverlap(
            listOf("10.0.0.0/24"), listOf("10.0.0.0/24")))
    }

    @Test fun `cidrsOverlap subnet contained in supernet`() {
        assertTrue(cidrsOverlap(
            listOf("10.0.5.0/24"), listOf("10.0.0.0/16")))
        // Symmetric — argument order doesn't matter.
        assertTrue(cidrsOverlap(
            listOf("10.0.0.0/16"), listOf("10.0.5.0/24")))
    }

    @Test fun `cidrsOverlap disjoint subnets return false`() {
        assertFalse(cidrsOverlap(
            listOf("10.0.0.0/24"), listOf("192.168.0.0/24")))
        assertFalse(cidrsOverlap(
            listOf("10.0.0.0/24"), listOf("10.1.0.0/24")))
    }

    @Test fun `cidrsOverlap catchall overlaps everything v4`() {
        assertTrue(cidrsOverlap(
            listOf("0.0.0.0/0"), listOf("10.0.0.0/24")))
        assertTrue(cidrsOverlap(
            listOf("10.0.0.0/24"), listOf("0.0.0.0/0")))
    }

    @Test fun `cidrsOverlap catchall overlaps single host v4`() {
        assertTrue(cidrsOverlap(
            listOf("0.0.0.0/0"), listOf("198.51.100.7/32")))
    }

    @Test fun `cidrsOverlap mixed families do not overlap`() {
        assertFalse(cidrsOverlap(
            listOf("0.0.0.0/0"), listOf("::/0")))
        assertFalse(cidrsOverlap(
            listOf("10.0.0.0/24"), listOf("fd00::/8")))
    }

    @Test fun `cidrsOverlap full-tunnel default overlaps user pool v4`() {
        // The compiled-in FULL_TUNNEL constant is "0.0.0.0/0,::/0";
        // tunnels that advertise it overlap with anything in v4 and v6.
        val full = listOf("0.0.0.0/0", "::/0")
        assertTrue(cidrsOverlap(full, listOf("10.99.0.0/24")))
        assertTrue(cidrsOverlap(full, listOf("2001:db8::/64")))
    }

    @Test fun `cidrsOverlap finds any one overlapping pair in lists`() {
        val a = listOf("10.0.0.0/24", "192.168.1.0/24")
        val b = listOf("172.16.0.0/12", "192.168.1.128/25")
        // Only the 192.168.1.128/25 ⊂ 192.168.1.0/24 pair overlaps;
        // the function returns true on first hit.
        assertTrue(cidrsOverlap(a, b))
    }

    @Test fun `cidrsOverlap silently skips malformed entries`() {
        val a = listOf("not-a-cidr", "10.0.0.0/24")
        val b = listOf("garbage", "10.0.0.128/25")
        assertTrue(cidrsOverlap(a, b))
        assertFalse(cidrsOverlap(
            listOf("not-a-cidr"), listOf("10.0.0.0/24")))
    }

    @Test fun `cidrsOverlap adjacent ranges do not overlap`() {
        // 10.0.0.0/25 = .0–.127; 10.0.0.128/25 = .128–.255 — touch
        // boundaries but share no addresses.
        assertFalse(cidrsOverlap(
            listOf("10.0.0.0/25"), listOf("10.0.0.128/25")))
    }

    // ─── cidrsShareExactPrefix ────────────────────────────────────────

    @Test fun `cidrsShareExactPrefix empty lists return false`() {
        assertFalse(cidrsShareExactPrefix(emptyList(), listOf("10.0.0.0/24")))
        assertFalse(cidrsShareExactPrefix(listOf("10.0.0.0/24"), emptyList()))
        assertFalse(cidrsShareExactPrefix(emptyList(), emptyList()))
    }

    @Test fun `cidrsShareExactPrefix identical CIDRs match`() {
        assertTrue(cidrsShareExactPrefix(
            listOf("10.0.0.0/24"), listOf("10.0.0.0/24")))
    }

    @Test fun `cidrsShareExactPrefix subnet relationship does NOT match`() {
        // Critical CASCADE-1 case: /16 contains /24, but they have
        // different prefix lengths — LPM resolves cleanly, no conflict.
        assertFalse(cidrsShareExactPrefix(
            listOf("10.0.5.0/24"), listOf("10.0.0.0/16")))
        assertFalse(cidrsShareExactPrefix(
            listOf("10.0.0.0/16"), listOf("10.0.5.0/24")))
    }

    @Test fun `cidrsShareExactPrefix full-tunnel and host subnet do NOT match`() {
        // The literal CASCADE-1 scenario: 0.0.0.0/0 vs 10.99.0.0/24.
        // Pre-fix this was treated as a conflict by cidrsOverlap;
        // post-fix this function returns false.
        assertFalse(cidrsShareExactPrefix(
            listOf("0.0.0.0/0"), listOf("10.99.0.0/24")))
        assertFalse(cidrsShareExactPrefix(
            listOf("10.99.0.0/24"), listOf("0.0.0.0/0")))
    }

    @Test fun `cidrsShareExactPrefix same network different prefix does NOT match`() {
        // Same base network address but different prefix lengths —
        // still LPM-resolvable.  /24 wins for the first 256 addresses,
        // /16 catches the rest.  No conflict.
        assertFalse(cidrsShareExactPrefix(
            listOf("10.0.0.0/24"), listOf("10.0.0.0/16")))
        assertFalse(cidrsShareExactPrefix(
            listOf("10.0.0.0/16"), listOf("10.0.0.0/24")))
    }

    @Test fun `cidrsShareExactPrefix disjoint CIDRs return false`() {
        assertFalse(cidrsShareExactPrefix(
            listOf("10.0.0.0/24"), listOf("192.168.0.0/24")))
    }

    @Test fun `cidrsShareExactPrefix v6 identical match`() {
        assertTrue(cidrsShareExactPrefix(
            listOf("fd00::/64"), listOf("fd00::/64")))
    }

    @Test fun `cidrsShareExactPrefix v6 different prefix does NOT match`() {
        // ::/0 vs fd00::/64 is the v6 version of CASCADE-1.
        assertFalse(cidrsShareExactPrefix(
            listOf("::/0"), listOf("fd00::/64")))
    }

    @Test fun `cidrsShareExactPrefix mixed families do not match`() {
        assertFalse(cidrsShareExactPrefix(
            listOf("0.0.0.0/0"), listOf("::/0")))
        assertFalse(cidrsShareExactPrefix(
            listOf("10.0.0.0/24"), listOf("fd00::/24")))
    }

    @Test fun `cidrsShareExactPrefix finds match in lists`() {
        val a = listOf("10.0.0.0/24", "192.168.1.0/24")
        val b = listOf("172.16.0.0/12", "192.168.1.0/24")
        // 192.168.1.0/24 appears identically in both.
        assertTrue(cidrsShareExactPrefix(a, b))
    }

    @Test fun `cidrsShareExactPrefix silently skips malformed entries`() {
        val a = listOf("not-a-cidr", "10.0.0.0/24")
        val b = listOf("garbage", "10.0.0.0/24")
        assertTrue(cidrsShareExactPrefix(a, b))
        assertFalse(cidrsShareExactPrefix(
            listOf("not-a-cidr"), listOf("10.0.0.0/24")))
    }

    @Test fun `cidrsShareExactPrefix host route inside subnet does NOT match`() {
        // /32 inside /24 — different prefix lengths.
        assertFalse(cidrsShareExactPrefix(
            listOf("10.0.0.5/32"), listOf("10.0.0.0/24")))
    }
}
