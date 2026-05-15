package com.gutschke.wgrtc.data

import java.math.BigInteger
import java.net.InetAddress
import java.security.SecureRandom

/**
 * IPv4 + IPv6 host allocator over a host-mode subnet.
 *
 * Pure / stateless — caller passes the subnet, the host's own IP, and
 * the set of currently-allocated peer IPs; allocator returns the next
 * free /32 (v4) or /128 (v6) (or null on exhaustion). Persistence is
 * the caller's job (the host-mode tunnel's tunnels.json entry).
 *
 * V6.2 adds the IPv6 sibling: a `generateUlaPrefix` factory that
 * mints a fresh per-tunnel `fd<random40>::/64` ULA per RFC 4193
 * §3.2.1, and a `nextFreeIpV6` allocator that mirrors the v4 path
 * for /128 joiner addresses inside the host's /64.  See
 * `docs/ipv6-design.md` V6.PL for the architectural argument that
 * ULA routes correctly through the userspace-NAT architecture.
 *
 * Allocation policy (both families): linear scan from the lowest
 * usable host address upward; first hole wins. This makes the IP a
 * peer gets stable on re-enrollment as long as no peer in front of
 * it has been removed — good enough for casual sharing scenarios;
 * if we ever need true stability across removals, that's the
 * caller's responsibility (key the in-use map by peer pubkey, reuse
 * the previous IP on re-enroll).
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

    // ── IPv6 sibling — V6.2 ───────────────────────────────────────

    /**
     * V6.2 — generate a fresh ULA prefix per RFC 4193 §3.2.1:
     * `fd<40 random bits>:<16-bit subnet=0>::/64`.  Rendered in
     * canonical lowercase compressed form (e.g. `fd1a:2b3c:4d5e::/64`).
     *
     * The 40 random bits are sampled from [rng]; calling with a
     * `SecureRandom` from outside the test path produces the global-
     * collision-probability claim ULAs are designed for.  RFC 4193
     * suggests deriving from EUI-64 + timestamp + SHA-1 for
     * "documentable uniqueness" — we punt on that and let the
     * pseudorandom 40 bits do the work, which is fine for the wgrtc
     * use case (host-to-joiner overlays that never share a routing
     * domain with another wgrtc tunnel).
     *
     * The 16-bit "subnet ID" field is left zero — each host-mode
     * tunnel gets its own freshly random /48 + a single /64 under
     * it, so there's no need to multiplex subnets within the
     * tunnel.
     */
    fun generateUlaPrefix(rng: SecureRandom = SecureRandom()): String {
        // Per RFC 4193: first byte is 0xfd, next 5 bytes are random.
        val bytes = ByteArray(6)
        rng.nextBytes(bytes)
        bytes[0] = 0xfd.toByte()
        // Render as "fdXX:XXXX:XXXX::/64".
        val seg0 = ((bytes[0].toInt() and 0xff) shl 8) or (bytes[1].toInt() and 0xff)
        val seg1 = ((bytes[2].toInt() and 0xff) shl 8) or (bytes[3].toInt() and 0xff)
        val seg2 = ((bytes[4].toInt() and 0xff) shl 8) or (bytes[5].toInt() and 0xff)
        return "%04x:%04x:%04x::/64".format(seg0, seg1, seg2)
    }

    /**
     * V6.2 — v6 sibling of [nextFreeIp].  Linear scan from
     * `(host's lowest byte) + 1` upward, returning the first free
     * /128 inside [subnet].  Returns null on malformed subnet,
     * host outside subnet, or exhaustion (only relevant in
     * absurdly-small subnets — a /64 has 2⁶⁴ candidates).
     *
     * Addresses are returned in canonical compressed lowercase
     * form (`InetAddress.getByName(...).hostAddress`).
     */
    fun nextFreeIpV6(subnet: String, hostIp: String, inUse: Set<String>): String? {
        val (netAddr, prefix) = parseV6Cidr(subnet) ?: return null
        if (prefix !in 0..128) return null
        val hostAddr = parseV6Strict(hostIp) ?: return null
        if (!inSubnetV6(hostAddr, netAddr, prefix)) return null

        // Build a canonical-form lookup set for inUse so callers
        // can pass either compressed or full-form addresses.
        val canonInUse = HashSet<String>(inUse.size * 2)
        for (s in inUse) {
            val canon = parseV6Strict(s) ?: continue
            canonInUse.add(addrToString(canon))
        }
        val canonHost = addrToString(hostAddr)

        // Network = the all-zero suffix of the prefix.  The host
        // sits somewhere inside it.  Linear scan starting at
        // hostAddr + 1 — matches the v4 convention of "host owns
        // .1, allocate .2 upward" without forcing a specific
        // policy on the host's suffix.
        var cur = hostAddr.add(BigInteger.ONE)
        val end = networkBroadcastV6(netAddr, prefix)
        // Cap the scan to avoid pathological behavior on /0.
        // 1 << 20 = 1M candidates is plenty for any realistic
        // allocation (way before that we'd be exhausted IRL).
        var iter = 0
        val limit = 1 shl 20
        while (cur <= end && iter < limit) {
            val candidate = addrToString(cur)
            if (candidate != canonHost && candidate !in canonInUse) {
                return candidate
            }
            cur = cur.add(BigInteger.ONE)
            iter++
        }
        return null
    }

    /** Parse "fd00::/64" → (networkAddr-as-BigInteger, prefix).
     * Returns null on malformed input. */
    private fun parseV6Cidr(s: String): Pair<BigInteger, Int>? {
        val trimmed = s.trim()
        if (trimmed.isEmpty()) return null
        val slash = trimmed.indexOf('/')
        val (host, prefixStr) = if (slash >= 0) {
            trimmed.substring(0, slash) to trimmed.substring(slash + 1)
        } else {
            trimmed to "128"
        }
        val addr = parseV6Strict(host) ?: return null
        val prefix = prefixStr.toIntOrNull() ?: return null
        if (prefix < 0 || prefix > 128) return null
        // Mask off host bits.
        val mask = v6Mask(prefix)
        return addr.and(mask) to prefix
    }

    /** Parse a v6 literal (no /prefix); returns BigInteger or null. */
    private fun parseV6Strict(s: String): BigInteger? {
        return try {
            val addr = InetAddress.getByName(s.trim())
            if (addr.address.size != 16) return null
            BigInteger(1, addr.address)
        } catch (_: Throwable) {
            null
        }
    }

    private fun v6Mask(prefix: Int): BigInteger {
        if (prefix == 0) return BigInteger.ZERO
        if (prefix == 128) return TWO_POW_128.subtract(BigInteger.ONE)
        val hostBits = 128 - prefix
        // (1<<128 - 1) << hostBits, then mask to 128 bits.
        val shifted = TWO_POW_128.subtract(BigInteger.ONE).shiftLeft(hostBits)
        return shifted.and(TWO_POW_128.subtract(BigInteger.ONE))
    }

    private fun networkBroadcastV6(netAddr: BigInteger, prefix: Int): BigInteger {
        if (prefix == 128) return netAddr
        val hostBits = 128 - prefix
        val hostMask = BigInteger.ONE.shiftLeft(hostBits).subtract(BigInteger.ONE)
        return netAddr.or(hostMask)
    }

    private fun inSubnetV6(addr: BigInteger, netAddr: BigInteger, prefix: Int): Boolean {
        if (prefix == 0) return true
        val mask = v6Mask(prefix)
        return addr.and(mask) == netAddr
    }

    /** Render a 128-bit BigInteger as a canonical RFC 5952
     * compressed lowercase v6 literal.  Done by hand instead of
     * via [InetAddress.getByAddress].hostAddress because the JVM
     * unit-test environment returns the long form (`fd00:0:0:0::1`-
     * style intermediate form on some JREs, `fd00:0:0:0:0:0:0:1`
     * on others), while Android's libcore returns the compressed
     * form.  We need a single representation so tests +
     * production agree byte-for-byte. */
    private fun addrToString(addr: BigInteger): String {
        val bytes = ByteArray(16)
        val srcBytes = addr.toByteArray()
        val start = if (srcBytes.size > 16) srcBytes.size - 16 else 0
        val srcLen = if (srcBytes.size > 16) 16 else srcBytes.size
        System.arraycopy(srcBytes, start, bytes, 16 - srcLen, srcLen)
        // Eight 16-bit segments.
        val segs = IntArray(8) { i ->
            ((bytes[i * 2].toInt() and 0xff) shl 8) or
                (bytes[i * 2 + 1].toInt() and 0xff)
        }
        // RFC 5952 §4.2: replace the longest run of zero segments
        // (length ≥ 2) with `::`.  Ties broken in favor of the
        // first such run.
        var bestStart = -1
        var bestLen = 0
        var i = 0
        while (i < 8) {
            if (segs[i] == 0) {
                var j = i
                while (j < 8 && segs[j] == 0) j++
                val len = j - i
                if (len > bestLen && len >= 2) {
                    bestLen = len
                    bestStart = i
                }
                i = j
            } else {
                i++
            }
        }
        val sb = StringBuilder()
        var p = 0
        while (p < 8) {
            if (p == bestStart) {
                // Emit `::` and skip the run.
                if (p == 0) sb.append(':')
                sb.append(':')
                p += bestLen
                if (p == 8) return sb.toString() // run goes to end
                continue
            }
            if (p > 0) sb.append(':')
            sb.append(segs[p].toString(16))
            p++
        }
        return sb.toString()
    }

    private val TWO_POW_128 = BigInteger.ONE.shiftLeft(128)
}
