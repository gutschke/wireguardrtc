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
}
