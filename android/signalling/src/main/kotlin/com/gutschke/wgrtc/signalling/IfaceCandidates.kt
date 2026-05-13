package com.gutschke.wgrtc.signalling

import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.NetworkInterface

/**
 * Iface-candidate classifier and ranker, mirror of the daemon's
 * `_classify_iface_addr` / `discover_local_candidates` in
 * `github/wireguardrtc`.
 *
 * Used to populate the `candidates` list a host advertises
 * in OFFER envelopes: the phone scans its own interfaces, classifies
 * each address (LAN / STUN / mesh / drop), ranks them, and ships the
 * resulting list so guests on its hotspot LAN can connect to the
 * 192.168.x.x address while clients off-LAN can fall back to a STUN-
 * discovered public IP.
 *
 * Pure JVM — no Android dependencies — so it tests cleanly under
 * `:signalling:test` and can be reused as-is in a future
 * Kotlin/Multiplatform port. Iface enumeration uses
 * `java.net.NetworkInterface` (available on both Android and the
 * JVM); tests inject a [IfaceAddrProvider] fake so they don't depend
 * on the host's network.
 *
 * Ranking convention (lowest first = most preferred): mirrors the
 * daemon's numeric ranks so OFFERs the host advertises are
 * indistinguishable from those the daemon would advertise:
 *
 * 20 — STUN, default iface (typical public-IP route)
 * 30 — STUN, non-default iface
 * 40 — LAN, bridge or globally-routable on bridge
 * 50 — LAN, RFC1918 + CGNAT (the workhorse; both hotspot-AP and
 * cellular-CGNAT fall here)
 * 60 — MESH, AdvertiseInterfaces explicit allowlist (user
 * deliberately opted this iface in)
 */

/** RFC 7335 CLAT stub network — never advertise as a candidate. */
private val CLAT_STUB_PREFIX = "192.0.0." // /29 = 192.0.0.0..192.0.0.7

private fun parseV4(ip: String): Inet4Address? = try {
    val a = InetAddress.getByName(ip)
    a as? Inet4Address
} catch (_: Exception) { null }

/** True iff [ip] is a v4 IP usable as a candidate. Mirrors the
 * daemon's `_is_candidate_eligible_v4`. */
fun isCandidateEligibleV4(ip: String): Boolean {
    val addr = parseV4(ip) ?: return false
    if (addr.isLoopbackAddress) return false
    if (addr.isLinkLocalAddress) return false
    if (addr.isMulticastAddress) return false
    if (addr.isAnyLocalAddress) return false // 0.0.0.0
    val bytes = addr.address
    val firstOctet = bytes[0].toInt() and 0xFF
    // Reserved (240/4): not classified as routable.
    if (firstOctet >= 240) return false
    // RFC 7335 CLAT stub 192.0.0.0/29 — drop.
    if (firstOctet == 192 &&
        (bytes[1].toInt() and 0xFF) == 0 &&
        (bytes[2].toInt() and 0xFF) == 0 &&
        (bytes[3].toInt() and 0xFF) <= 7
    ) return false
    return true
}

private fun parseV6(ip: String): Inet6Address? = try {
    val a = InetAddress.getByName(ip)
    a as? Inet6Address
} catch (_: Exception) { null }

/** Result of [classifyV6Range] — what kind of IPv6 address [ip] is
 * from the candidate-advertising point of view. */
enum class V6Range {
    /** Globally-routable unicast (`2000::/3`). Publicly reachable
     * across the internet (modulo ISP inbound firewall policy);
     * treated like a STUN-discovered v4 address by the ranker. */
    GLOBAL,

    /** Unique-Local Address (`fc00::/7`, covering `fc00::/8` and
     * `fd00::/8`). Routable across the home LAN / site but NOT over
     * the public internet. Useful as a LAN candidate when both
     * peers share the same site-internal prefix. Usually faster
     * than the global v6 because traffic stays on the user's
     * router rather than hairpinning through the ISP. */
    ULA,

    /** Not advertise-able (link-local, multicast, loopback,
     * IPv4-mapped, unspecified, etc.). */
    NONE,
}

/**
 * Categorize an IPv6 literal for the candidate ranker. Returns
 * [V6Range.NONE] for any address that can't usefully be advertised
 * to a remote peer (link-local needs a scope id; site-local is
 * deprecated; ::, ::1, ff::/8, ::ffff:/96 are all dead-end). Both
 * GLOBAL and ULA are advertise-able but get different ranks /
 * `kind` labels downstream — see [classifyIfaceAddr].
 */
fun classifyV6Range(ip: String): V6Range {
    val addr = parseV6(ip) ?: return V6Range.NONE
    if (addr.isLoopbackAddress) return V6Range.NONE
    if (addr.isLinkLocalAddress) return V6Range.NONE
    if (addr.isSiteLocalAddress) return V6Range.NONE   // deprecated fec0::/10
    if (addr.isMulticastAddress) return V6Range.NONE
    if (addr.isAnyLocalAddress) return V6Range.NONE    // ::
    // ::ffff:0:0/96 (IPv4-mapped) is auto-unwrapped to an
    // Inet4Address by InetAddress.getByName, so parseV6 already
    // rejected it. ::/96 (IPv4-compatible, deprecated) is still
    // returned as an Inet6Address; reject explicitly.
    if (addr.isIPv4CompatibleAddress) return V6Range.NONE
    val b = addr.address
    val first = b[0].toInt() and 0xFF
    // Unique-local fc00::/7 (covers both fc00::/8 and fd00::/8).
    if ((first and 0xFE) == 0xFC) return V6Range.ULA
    // Global unicast space is 2000::/3 — first 3 bits are 001.
    if ((first and 0xE0) == 0x20) return V6Range.GLOBAL
    return V6Range.NONE
}

/** True iff [ip] is an IPv6 address suitable to advertise as an
 * endpoint candidate (global unicast or ULA). Thin wrapper around
 * [classifyV6Range] for callers that only need a yes/no. */
fun isCandidateEligibleV6(ip: String): Boolean =
    classifyV6Range(ip) != V6Range.NONE

/** True iff [ip] is RFC 1918 private *or* CGNAT (100.64/10).
 * Mirrors the daemon's `_is_private_v4`. */
fun isPrivateV4(ip: String): Boolean {
    val addr = parseV4(ip) ?: return false
    val b = addr.address
    val o0 = b[0].toInt() and 0xFF
    val o1 = b[1].toInt() and 0xFF
    // 10/8
    if (o0 == 10) return true
    // 172.16/12
    if (o0 == 172 && o1 in 16..31) return true
    // 192.168/16
    if (o0 == 192 && o1 == 168) return true
    // 100.64/10 (CGNAT)
    if (o0 == 100 && o1 in 64..127) return true
    return false
}

/** True for Linux interface names that are typically tunnels —
 * excluded from candidate advertising unless explicitly allowlisted. */
fun isTunnelIfaceName(iface: String): Boolean {
    if (iface.startsWith("wg")) return true
    if (iface.startsWith("tun")) return true
    if (iface.startsWith("tap")) return true
    if (iface.startsWith("ppp")) return true
    if (iface.startsWith("gre")) return true
    if (iface.startsWith("ipsec")) return true
    return false
}

/** True for typical bridge-iface names. */
fun isBridgeIfaceName(iface: String): Boolean {
    if (iface.startsWith("br")) return true // br0, br-XXXX
    if (iface.startsWith("vmbr")) return true // proxmox
    if (iface.startsWith("docker")) return true // docker0
    if (iface.startsWith("virbr")) return true // libvirt
    if (iface.startsWith("lxcbr")) return true
    return false
}

/**
 * Classify a single (iface, ip) pair. Returns `(rank, kind)` if the
 * pair should be advertised, or `null` if dropped. Mirrors the
 * daemon's `_classify_iface_addr` exactly so the host advertises the
 * same shapes of candidates the client side already knows.
 *
 * Handles both IPv4 and IPv6 inputs. v6 globally-routable addresses
 * get rank 25 (between v4-default-iface STUN at 20 and v4-non-default
 * at 30) and `kind = "stun"` — they are publicly reachable without
 * NAT and so functionally play the same role as a STUN-discovered v4
 * public IP, just without the round-trip through a STUN server. ULA
 * / link-local / scoped v6 addresses are dropped by
 * [isCandidateEligibleV6].
 */
fun classifyIfaceAddr(
    iface: String,
    ip: String,
    defaultIface: String?,
    advertise: Set<String>,
    suppress: Set<String>,
    ownWg: Set<String>,
): Pair<Int, String>? {
    if (iface in ownWg) return null
    if (iface in suppress) return null
    if (isTunnelIfaceName(iface) && iface !in advertise) return null

    // IPv6 path. Two flavours of v6 land here: globally-routable
    // unicast (publicly reachable, no NAT — treated like a
    // STUN-discovered v4 public IP) and ULA (site-local, faster
    // than global when both peers share the same router but not
    // routable across the public internet — treated like a v4 LAN
    // candidate). Mesh allowlist overrides both. Link-local /
    // multicast / scoped addresses are dropped by classifyV6Range.
    // The daemon doesn't emit v6 candidates today; introducing them
    // on the Android side is forward-compatible because the wire
    // format already carries `kind` as a free-form string and the
    // receiver only uses it for ordering.
    if (':' in ip) {
        if (iface in advertise) {
            return if (classifyV6Range(ip) != V6Range.NONE) 60 to "mesh" else null
        }
        return when (classifyV6Range(ip)) {
            V6Range.GLOBAL -> 25 to "stun"
            V6Range.ULA -> 45 to "lan"
            V6Range.NONE -> null
        }
    }

    // IPv4 path.
    if (!isCandidateEligibleV4(ip)) return null

    if (iface in advertise) return 60 to "mesh"

    if (isPrivateV4(ip)) {
        return if (isBridgeIfaceName(iface)) 40 to "lan" else 50 to "lan"
    }
    if (isBridgeIfaceName(iface)) return 40 to "lan"

    return if (defaultIface != null && iface == defaultIface) {
        20 to "stun"
    } else {
        30 to "stun"
    }
}

/**
 * One classified, ranked candidate from a host's iface enumeration.
 * `kind` matches the daemon's wire-format kind values
 * (`"stun" | "lan" | "mesh"`); the same string lands in the
 * `candidates[].kind` field of the encrypted OFFER blob.
 */
data class IfaceCandidate(
    val iface: String,
    val ip: String,
    val rank: Int,
    val kind: String,
)

/** Test seam — production code uses [JavaIfaceAddrProvider]. */
interface IfaceAddrProvider {
    /** Returns `(iface, ip-string)` pairs. May include IPv4 and/or
     * IPv6 literals. Insertion order is preserved through
     * ranking-stable sort downstream. */
    fun list(): List<Pair<String, String>>
}

/** Production iface enumerator using `java.net.NetworkInterface`.
 * Emits both IPv4 and IPv6 addresses; the ranker drops the unwanted
 * v6 ranges (link-local / ULA / scoped) via
 * [isCandidateEligibleV6]. Skips IPv6 addresses that carry a
 * Java scope id (e.g. `fe80::…%wlan0`) — those are by definition
 * not globally routable. */
class JavaIfaceAddrProvider : IfaceAddrProvider {
    override fun list(): List<Pair<String, String>> {
        val out = mutableListOf<Pair<String, String>>()
        val ifaces = NetworkInterface.getNetworkInterfaces() ?: return out
        for (ni in ifaces) {
            if (!ni.isUp) continue
            for (a in ni.inetAddresses) {
                when (a) {
                    is Inet4Address -> out += ni.name to a.hostAddress!!
                    is Inet6Address -> {
                        val s = a.hostAddress ?: continue
                        // Strip the optional %scopeId suffix; the
                        // eligibility filter rejects scoped addresses
                        // anyway, but defensive.
                        val bare = s.substringBefore('%')
                        out += ni.name to bare
                    }
                }
            }
        }
        return out
    }
}

/**
 * Run [provider] and rank the results. Drops dropped entries,
 * deduplicates by IP (first occurrence wins), sorts ascending by
 * rank with insertion-stable tiebreak.
 */
fun enumerateAndRank(
    provider: IfaceAddrProvider,
    defaultIface: String?,
    advertise: Set<String> = emptySet(),
    suppress: Set<String> = emptySet(),
    ownWg: Set<String> = emptySet(),
    cap: Int = 10,
): List<IfaceCandidate> {
    val seen = mutableSetOf<String>()
    val kept = mutableListOf<IfaceCandidate>()
    var insertionOrder = 0
    for ((iface, ip) in provider.list()) {
        if (ip in seen) continue
        val cls = classifyIfaceAddr(iface, ip, defaultIface, advertise, suppress, ownWg)
            ?: continue
        seen += ip
        kept += IfaceCandidate(iface = iface, ip = ip, rank = cls.first, kind = cls.second)
        insertionOrder += 1
    }
    // Sort by rank ascending; List.sortedBy is stable (insertion order
    // preserved for equal-rank entries — matches the daemon's behavior).
    return kept.sortedBy { it.rank }.take(cap)
}
