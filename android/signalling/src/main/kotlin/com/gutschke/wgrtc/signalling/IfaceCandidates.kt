package com.gutschke.wgrtc.signalling

import java.net.Inet4Address
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
    if (!isCandidateEligibleV4(ip)) return null
    if (isTunnelIfaceName(iface) && iface !in advertise) return null

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
    /** Returns `(iface, ip-string)` pairs. IPv4 only. Insertion
     * order is preserved through ranking-stable sort downstream. */
    fun list(): List<Pair<String, String>>
}

/** Production iface enumerator using `java.net.NetworkInterface`. */
class JavaIfaceAddrProvider : IfaceAddrProvider {
    override fun list(): List<Pair<String, String>> {
        val out = mutableListOf<Pair<String, String>>()
        val ifaces = NetworkInterface.getNetworkInterfaces() ?: return out
        for (ni in ifaces) {
            if (!ni.isUp) continue
            for (a in ni.inetAddresses) {
                if (a is Inet4Address) {
                    out += ni.name to a.hostAddress!!
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
    // preserved for equal-rank entries — matches the daemon's behaviour).
    return kept.sortedBy { it.rank }.take(cap)
}
