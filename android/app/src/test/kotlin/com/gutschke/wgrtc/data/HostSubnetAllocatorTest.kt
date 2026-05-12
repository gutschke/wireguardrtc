package com.gutschke.wgrtc.data

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

/**
 * Unit tests for [HostSubnetAllocator] — IPv4 host allocator over a
 * host-mode subnet.
 *
 * Pure-stateless API: caller passes in current allocations,
 * allocator returns the next free /32 (or null on exhaustion).
 * Persistence is the caller's responsibility (the host-mode tunnel's
 * tunnels.json entry, .4).
 */
class HostSubnetAllocatorTest {

    @Test fun `next free in empty 24 starts at 2`() {
        val ip = HostSubnetAllocator.nextFreeIp("10.99.0.0/24", "10.99.0.1", emptySet())
        assertEquals("10.99.0.2", ip)
    }

    @Test fun `next free skips host ip`() {
        val ip = HostSubnetAllocator.nextFreeIp("10.99.0.0/24", "10.99.0.5", emptySet())
        // .1 is first usable; not the host so it's allocated.
        assertEquals("10.99.0.1", ip)
    }

    @Test fun `next free skips already-allocated`() {
        val inUse = setOf("10.99.0.2", "10.99.0.3", "10.99.0.4")
        val ip = HostSubnetAllocator.nextFreeIp("10.99.0.0/24", "10.99.0.1", inUse)
        assertEquals("10.99.0.5", ip)
    }

    @Test fun `next free finds a hole`() {
        val inUse = setOf("10.99.0.2", "10.99.0.4", "10.99.0.5", "10.99.0.6")
        val ip = HostSubnetAllocator.nextFreeIp("10.99.0.0/24", "10.99.0.1", inUse)
        assertEquals("10.99.0.3", ip)
    }

    @Test fun `next free skips network and broadcast in 24`() {
        // .0 = network, .255 = broadcast — never returned.
        val all = (0..255).map { "10.99.0.$it" }.toSet() -
            setOf("10.99.0.0", "10.99.0.255", "10.99.0.99")
        val ip = HostSubnetAllocator.nextFreeIp("10.99.0.0/24", "10.99.0.1", all)
        assertEquals("10.99.0.99", ip)
    }

    @Test fun `next free returns null when exhausted`() {
        val all = (1..254).map { "10.99.0.$it" }.toSet()
        val ip = HostSubnetAllocator.nextFreeIp("10.99.0.0/24", "10.99.0.1", all)
        assertNull(ip)
    }

    @Test fun `next free works with 29 subnet (8 addresses, 6 hosts)`() {
        // 10.99.0.0/29 covers .0..7, hosts are .1..6, so .2 first w/ host=.1.
        val ip = HostSubnetAllocator.nextFreeIp("10.99.0.0/29", "10.99.0.1", emptySet())
        assertEquals("10.99.0.2", ip)
    }

    @Test fun `next free in 29 exhausts after host count`() {
        val all = setOf("10.99.0.2", "10.99.0.3", "10.99.0.4", "10.99.0.5", "10.99.0.6")
        val ip = HostSubnetAllocator.nextFreeIp("10.99.0.0/29", "10.99.0.1", all)
        assertNull(ip)
    }

    @Test fun `next free works at non-zero offsets`() {
        val ip = HostSubnetAllocator.nextFreeIp("192.168.43.0/24", "192.168.43.1", emptySet())
        assertEquals("192.168.43.2", ip)
    }

    @Test fun `next free handles bare IP as 32 (single host, no allocation possible)`() {
        // /32 has 1 address; if it's the host's, no allocations possible.
        val ip = HostSubnetAllocator.nextFreeIp("10.99.0.5/32", "10.99.0.5", emptySet())
        assertNull(ip)
    }

    @Test fun `next free returns null for malformed subnet`() {
        assertNull(HostSubnetAllocator.nextFreeIp("not-a-cidr", "10.0.0.1", emptySet()))
        assertNull(HostSubnetAllocator.nextFreeIp("10.0.0.0/99", "10.0.0.1", emptySet()))
        assertNull(HostSubnetAllocator.nextFreeIp("", "10.0.0.1", emptySet()))
    }

    @Test fun `next free returns null when host ip is not in the subnet`() {
        // Misconfiguration: host ip 192.168.1.1 isn't in 10.99.0.0/24.
        // Caller should detect this earlier; allocator returns null defensively.
        val ip = HostSubnetAllocator.nextFreeIp("10.99.0.0/24", "192.168.1.1", emptySet())
        assertNull(ip)
    }

    @Test fun `usableAddresses lists all hosts in 24 minus net and broadcast`() {
        val hosts = HostSubnetAllocator.usableAddresses("10.99.0.0/24")
        assertEquals(254, hosts.size)
        assertEquals("10.99.0.1", hosts.first())
        assertEquals("10.99.0.254", hosts.last())
        assertFalse(hosts.contains("10.99.0.0"))
        assertFalse(hosts.contains("10.99.0.255"))
    }

    @Test fun `usableAddresses for 29`() {
        val hosts = HostSubnetAllocator.usableAddresses("10.99.0.0/29")
        assertEquals(6, hosts.size)
        assertEquals(listOf(
            "10.99.0.1", "10.99.0.2", "10.99.0.3",
            "10.99.0.4", "10.99.0.5", "10.99.0.6"
        ), hosts)
    }
}
