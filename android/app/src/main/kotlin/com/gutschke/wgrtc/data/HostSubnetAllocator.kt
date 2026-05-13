package com.gutschke.wgrtc.data

/**
 * IPv4 host allocator over a host-mode subnet.
 *
 * Pure / stateless — caller passes the subnet, the host's own IP, and
 * the set of currently-allocated peer IPs; allocator returns the next
 * free /32 (or null on exhaustion). Persistence is the caller's job
 * (4: the host-mode tunnel's tunnels.json entry).
 *
 * IPv4 only. IPv6 host-mode isn't on the roadmap; if/when
 * it is, this gets a v6 sibling.
 *
 * Allocation policy: linear scan from the lowest usable host address
 * upward; first hole wins. This makes the IP a peer gets stable on
 * re-enrollment as long as no peer in front of it has been removed —
 * good enough for casual sharing scenarios; if we ever need true
 * stability across removals, that's the caller's responsibility (key
 * the in-use map by peer pubkey, reuse the previous IP on re-enroll).
 */
object HostSubnetAllocator {

    /**
     * Find the next free IPv4 address in [subnet] (CIDR), skipping the
     * network address, broadcast address, [hostIp], and anything in
     * [inUse]. Returns the IP as a dotted-quad string, or null if the
     * subnet is exhausted, malformed, or [hostIp] doesn't fall inside
     * it.
     */
    fun nextFreeIp(subnet: String, hostIp: String, inUse: Set<String>): String? {
        val (netInt, prefix) = parseV4Cidr(subnet) ?: return null
        if (prefix !in 0..32) return null

        // /32 carries one address; it's either the host or it's free.
        // No hosts can be allocated in a /32 that the host owns.
        if (prefix == 32) {
            val onlyAddr = intToDotted(netInt)
            if (onlyAddr == hostIp) return null
            if (onlyAddr in inUse) return null
            return onlyAddr
        }

        // Defensive: host must lie in the subnet, otherwise the caller
        // is misconfigured. Don't allocate anything that would route
        // traffic to a host the WG tunnel can't reach.
        val hostInt = parseV4(hostIp) ?: return null
        if (!inSubnet(hostInt, netInt, prefix)) return null

        val firstUsable = netInt + 1L // skip network
        val lastUsable = networkBroadcast(netInt, prefix) - 1L
        if (firstUsable > lastUsable) return null

        var ip = firstUsable
        while (ip <= lastUsable) {
            val dotted = intToDotted(ip)
            if (dotted != hostIp && dotted !in inUse) return dotted
            ip += 1
        }
        return null
    }

    /** All usable host addresses in [subnet] (network + broadcast
     * excluded for prefix < 31). Returns empty for malformed input. */
    fun usableAddresses(subnet: String): List<String> {
        val (netInt, prefix) = parseV4Cidr(subnet) ?: return emptyList()
        if (prefix !in 0..32) return emptyList()
        if (prefix == 32) return listOf(intToDotted(netInt))
        if (prefix == 31) {
            // RFC 3021: both addresses are usable on a /31.
            // doesn't deploy /31 host-mode in practice, but be correct.
            return listOf(intToDotted(netInt), intToDotted(netInt + 1))
        }
        val first = netInt + 1L
        val last = networkBroadcast(netInt, prefix) - 1L
        if (first > last) return emptyList()
        return (first..last).map(::intToDotted)
    }

    // ── internals ────────────────────────────────────────────────────

    /** Parse a v4 CIDR ("a.b.c.d/N"). Bare IP → /32. Returns
     * `(networkAddrAsLong, prefix)` or null on malformed input. */
    private fun parseV4Cidr(s: String): Pair<Long, Int>? {
        val trimmed = s.trim()
        if (trimmed.isEmpty()) return null
        val (host, prefixStr) = if ("/" in trimmed) {
            val parts = trimmed.split("/", limit = 2)
            parts[0] to parts[1]
        } else {
            trimmed to "32"
        }
        val ip = parseV4(host) ?: return null
        val prefix = prefixStr.toIntOrNull() ?: return null
        if (prefix < 0 || prefix > 32) return null
        // Mask off host bits to get the canonical network address.
        val mask = if (prefix == 0) 0L else (-1L shl (32 - prefix)) and 0xFFFFFFFFL
        val net = ip and mask
        return net to prefix
    }

    private fun parseV4(s: String): Long? {
        val parts = s.split(".")
        if (parts.size != 4) return null
        var out = 0L
        for (p in parts) {
            val n = p.toIntOrNull() ?: return null
            if (n !in 0..255) return null
            out = (out shl 8) or n.toLong()
        }
        return out and 0xFFFFFFFFL
    }

    private fun intToDotted(n: Long): String {
        val a = (n shr 24) and 0xFF
        val b = (n shr 16) and 0xFF
        val c = (n shr 8) and 0xFF
        val d = n and 0xFF
        return "$a.$b.$c.$d"
    }

    private fun networkBroadcast(netInt: Long, prefix: Int): Long {
        if (prefix == 32) return netInt
        val hostBits = 32 - prefix
        return netInt or ((1L shl hostBits) - 1)
    }

    private fun inSubnet(addr: Long, netInt: Long, prefix: Int): Boolean {
        if (prefix == 0) return true
        val mask = (-1L shl (32 - prefix)) and 0xFFFFFFFFL
        return (addr and mask) == netInt
    }
}
