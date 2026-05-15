package com.gutschke.wgrtc.data

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.security.SecureRandom

/**
 * V6.2 — unit tests for [HostSubnetAllocator]'s v6 sibling API.
 *
 * Two new entry points:
 *
 *   - `generateUlaPrefix(rng)` — produces a fresh `fd<random40>::/64`
 *     ULA prefix per RFC 4193 §3.2.1.  V6.PL established that random
 *     ULA routes correctly through the userspace-NAT architecture;
 *     this is the wire-in for per-tunnel generation.
 *   - `nextFreeIpV6(subnet, hostIp, inUse)` — v6 sibling of
 *     [HostSubnetAllocator.nextFreeIp], allocating /128 joiner
 *     addresses inside the host's /64.
 *
 * Allocation policy mirrors the v4 path: linear scan from the lowest
 * usable address upward, first hole wins.  We start at the host's
 * suffix + 1 (typically `fd...::2`) since the host owns `::1` by
 * convention.
 */
class HostSubnetAllocatorV6Test {

    // ── generateUlaPrefix ────────────────────────────────────

    @Test fun `generateUlaPrefix starts with fd and ends with slash 64`() {
        val rng = SecureRandom("v6.2-seed".toByteArray())
        val cidr = HostSubnetAllocator.generateUlaPrefix(rng)
        assertTrue(cidr.startsWith("fd"), "ULA must start with fd; got $cidr")
        assertTrue(cidr.endsWith("/64"), "ULA must end with /64; got $cidr")
    }

    @Test fun `generateUlaPrefix has exactly 40 random bits after fd`() {
        // fd<40 random bits><16 bits subnet=0>::/64  →  "fdXX:XXXX:XXXX::/64"
        // 40 bits = 10 hex chars; rendered as "fdXX:XXXX:XXXX" (the
        // first hex pair includes the leading "fd" byte: 11111101
        // XXXXXXXX where Xs are random).
        val rng = SecureRandom("seed-1".toByteArray())
        val cidr = HostSubnetAllocator.generateUlaPrefix(rng)
        // Strip "/64", expand "::" → check the host part is zero.
        val net = cidr.removeSuffix("/64")
        // "fdXX:XXXX:XXXX::" form expected.
        assertTrue(net.endsWith("::"),
            "expected ULA prefix to end with `::` (16-bit subnet=0 + zero suffix); got $net")
        val segs = net.removeSuffix("::").split(':')
        assertEquals(3, segs.size,
            "expected three 16-bit segments before ::, got ${segs.size}: $net")
        assertTrue(segs[0].startsWith("fd"),
            "first segment must start with fd; got ${segs[0]}")
        assertEquals(4, segs[0].length, "fd<XX> must be 4 hex chars; got ${segs[0]}")
        assertEquals(4, segs[1].length)
        assertEquals(4, segs[2].length)
    }

    @Test fun `generateUlaPrefix produces different prefixes for different rng state`() {
        val a = HostSubnetAllocator.generateUlaPrefix(SecureRandom("seed-A".toByteArray()))
        val b = HostSubnetAllocator.generateUlaPrefix(SecureRandom("seed-B".toByteArray()))
        assertNotEquals(a, b, "different seeds should yield different ULA prefixes")
    }

    @Test fun `generateUlaPrefix output parses back through nextFreeIpV6`() {
        // End-to-end: take a freshly minted ULA and feed it into the
        // allocator with a host suffix of ::1.  Should successfully
        // allocate ::2.
        val rng = SecureRandom("seed-roundtrip".toByteArray())
        val cidr = HostSubnetAllocator.generateUlaPrefix(rng)
        val net = cidr.removeSuffix("/64")
        val hostIp = net + "1" // "fd...::1"
        val firstFree = HostSubnetAllocator.nextFreeIpV6(cidr, hostIp, emptySet())
        assertNotNull(firstFree, "freshly minted ULA must allocate at least one /128")
        assertTrue(firstFree!!.startsWith(net),
            "allocated address must lie in the generated subnet; got $firstFree")
        assertTrue(firstFree.endsWith(":2") || firstFree.endsWith("::2"),
            "expected suffix `:2` (or `::2`) for first joiner; got $firstFree")
    }

    // ── nextFreeIpV6 — basic allocation ──────────────────────

    @Test fun `nextFreeIpV6 in empty subnet starts at host plus 1`() {
        val ip = HostSubnetAllocator.nextFreeIpV6(
            "fd00:1234:5678::/64",
            "fd00:1234:5678::1",
            emptySet(),
        )
        assertEquals("fd00:1234:5678::2", ip)
    }

    @Test fun `nextFreeIpV6 skips host ip`() {
        val ip = HostSubnetAllocator.nextFreeIpV6(
            "fd00:1234:5678::/64",
            "fd00:1234:5678::1",
            emptySet(),
        )
        assertNotEquals("fd00:1234:5678::1", ip,
            "host's own address must never be returned")
    }

    @Test fun `nextFreeIpV6 skips already-allocated`() {
        val inUse = setOf(
            "fd00:1234:5678::2",
            "fd00:1234:5678::3",
            "fd00:1234:5678::4",
        )
        val ip = HostSubnetAllocator.nextFreeIpV6(
            "fd00:1234:5678::/64",
            "fd00:1234:5678::1",
            inUse,
        )
        assertEquals("fd00:1234:5678::5", ip)
    }

    @Test fun `nextFreeIpV6 finds a hole`() {
        val inUse = setOf(
            "fd00:1234:5678::2",
            "fd00:1234:5678::4",
            "fd00:1234:5678::5",
        )
        val ip = HostSubnetAllocator.nextFreeIpV6(
            "fd00:1234:5678::/64",
            "fd00:1234:5678::1",
            inUse,
        )
        assertEquals("fd00:1234:5678::3", ip)
    }

    @Test fun `nextFreeIpV6 rejects malformed subnet`() {
        assertNull(HostSubnetAllocator.nextFreeIpV6(
            "garbage::/64", "fd00::1", emptySet()))
        assertNull(HostSubnetAllocator.nextFreeIpV6(
            "fd00:1234:5678::/garbage", "fd00:1234:5678::1", emptySet()))
        assertNull(HostSubnetAllocator.nextFreeIpV6(
            "", "fd00::1", emptySet()))
    }

    @Test fun `nextFreeIpV6 rejects host outside subnet`() {
        // Host is in fd00::/64; subnet says fd01::/64.
        val ip = HostSubnetAllocator.nextFreeIpV6(
            "fd01:1234:5678::/64",
            "fd00:1234:5678::1",
            emptySet(),
        )
        assertNull(ip, "host must lie inside the subnet")
    }

    @Test fun `nextFreeIpV6 normalises canonical hex (lowercase, no leading zeros)`() {
        // Caller might pass `FD00:1234:5678::1` uppercase.  Allocator
        // should still recognise it + compare correctly.  Also handles
        // `0123` vs `123` segment forms.
        val ip = HostSubnetAllocator.nextFreeIpV6(
            "fd00:1234:5678::/64",
            "FD00:1234:5678::1",
            emptySet(),
        )
        assertEquals("fd00:1234:5678::2", ip)
    }

    @Test fun `nextFreeIpV6 in deep subnet allocates many addresses sequentially`() {
        // /64 has 2^64 addresses; verify the first 10 allocate
        // sequentially.  This confirms the linear-scan logic doesn't
        // bail early on the absurdly large range.
        val inUse = mutableSetOf<String>()
        val host = "fd00:1234:5678::1"
        for (i in 2..11) {
            val ip = HostSubnetAllocator.nextFreeIpV6(
                "fd00:1234:5678::/64", host, inUse)
            assertNotNull(ip, "iteration $i must allocate (got null)")
            assertEquals("fd00:1234:5678::${i.toString(16)}", ip,
                "iteration $i mismatch")
            inUse.add(ip!!)
        }
    }
}
