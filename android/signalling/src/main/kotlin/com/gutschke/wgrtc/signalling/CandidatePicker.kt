package com.gutschke.wgrtc.signalling

import java.net.InetAddress
import java.net.NetworkInterface

/**
 * Receiver-side candidate picker — Step D of the candidate-negotiation
 * v2 design.
 *
 * Responsibilities (the pure-JVM half):
 * 1. **Same-subnet detection.** For each LAN-flavour candidate,
 * check whether any of the receiver's local interfaces has an IP
 * in the same subnet (using the *receiver's* netmask, not
 * /24-by-assumption). Same-subnet candidates rank above
 * everything — they're the load-bearing hotspot guarantee.
 * 2. **Strict-mode fail-stop.** If at least one candidate is
 * same-subnet AND the caller asked for strict-mode (the
 * hotspot-aware default for ENROLL tunnels), the picker drops
 * every non-same-subnet candidate. Falling back to
 * cellular/STUN when same-LAN was offered would silently bill
 * cellular data and quadruple latency — a worse failure mode
 * than a clear "local-only failed" error.
 *
 * The Android-runtime half (`ConnectivityManager.bindSocket` egress
 * binding when a same-subnet candidate is chosen) layers on top of
 * this in Step F when the WG handshake race is wired up. This file
 * is pure JVM so the strict-mode logic and same-subnet ranking can be
 * exhaustively unit-tested without an emulator.
 */

/** A snapshot of one of the receiver's own network interface
 * addresses. Constructed via [enumerateLocalInterfaces] in
 * production; tests pass synthetic instances directly. */
data class LocalInterface(
    val name: String,
    val ip: String,
    val prefixBits: Int,
)

/** A candidate paired with the receiver-side egress decision the
 * picker made for it. [egressInterface] is non-null only when the
 * candidate matched a same-subnet local interface — that's the
 * iface the connection setup must bind the WG socket to (Step F). */
data class PickedCandidate(
    val candidate: EndpointUpdate,
    val egressInterface: String?,
    val isSameSubnet: Boolean,
)

/**
 * Find which local interface (if any) shares a subnet with [ip].
 * Returns the matching [LocalInterface] or null. When multiple
 * interfaces match (rare — a host with overlapping subnets), the
 * first match in [interfaces] order wins.
 */
fun matchSameSubnet(ip: String, interfaces: List<LocalInterface>): LocalInterface? {
    val candidateBytes = try { InetAddress.getByName(ip).address }
                         catch (_: Exception) { return null }
    for (iface in interfaces) {
        val ifaceBytes = try { InetAddress.getByName(iface.ip).address }
                         catch (_: Exception) { continue }
        if (cidrContains(ifaceBytes, iface.prefixBits, candidateBytes)) return iface
    }
    return null
}

/**
 * Pick the receiver-side ordering for [candidates], applying the
 * same-subnet override and strict-mode policy.
 *
 * - If any candidate is same-subnet: those candidates (in their
 * original sender-order) come first. The `egressInterface`
 * field on each [PickedCandidate] tells the connection setup
 * which Android `Network` to bind the WG socket to (Step F).
 * - If [strictHotspot] is true AND at least one same-subnet match
 * exists: every non-same-subnet candidate is dropped. The
 * caller surfaces "local-only failed" if the survivors all fail.
 * - Otherwise: same-subnet candidates first, non-same-subnet
 * after. Caller may fall through.
 *
 * If no candidate is same-subnet, the order is preserved unchanged
 * (sender-rank applies). An empty input yields an empty output.
 */
fun pickReceiverCandidates(
    candidates: List<EndpointUpdate>,
    interfaces: List<LocalInterface>,
    strictHotspot: Boolean = false,
): List<PickedCandidate> {
    if (candidates.isEmpty()) return emptyList()
    val annotated = candidates.map { c ->
        val match = matchSameSubnet(c.ip, interfaces)
        PickedCandidate(
            candidate = c,
            egressInterface = match?.name,
            isSameSubnet = match != null,
        )
    }
    val sameSubnet = annotated.filter { it.isSameSubnet }
    val others = annotated.filter { !it.isSameSubnet }
    return when {
        sameSubnet.isEmpty() -> others // no override, preserve sender order
        strictHotspot -> sameSubnet // strict: no fall-through
        else -> sameSubnet + others
    }
}

/**
 * Production helper: enumerate the receiver's currently-active local
 * v4 interfaces using [NetworkInterface.getNetworkInterfaces]. Skips
 * loopback, link-local, and operationally-down interfaces — same
 * gate the sender uses on its own enumeration. Returns an empty
 * list on any reflection / I/O failure (defensive: the caller falls
 * through to no-same-subnet behaviour, which is permissive but
 * doesn't deadlock).
 *
 * Pure JVM API — works on Android (ART supports `NetworkInterface`)
 * AND in unit tests. In tests we usually pass synthetic
 * [LocalInterface] lists directly to [pickReceiverCandidates] to
 * avoid depending on the host machine's actual interfaces.
 */
fun enumerateLocalInterfaces(): List<LocalInterface> {
    val out = mutableListOf<LocalInterface>()
    try {
        val ifaces = NetworkInterface.getNetworkInterfaces() ?: return emptyList()
        for (iface in ifaces) {
            if (!iface.isUp) continue
            if (iface.isLoopback) continue
            for (ifAddr in iface.interfaceAddresses) {
                val addr = ifAddr.address ?: continue
                if (addr.isLoopbackAddress) continue
                if (addr.isLinkLocalAddress) continue
                if (addr.isMulticastAddress) continue
                if (addr.isAnyLocalAddress) continue
                // We only care about v4 here — the hotspot guarantee
                // is v4-scoped and the candidate protocol is v4-only.
                // v6 same-subnet detection is forward work.
                if (addr.address.size != 4) continue
                out.add(LocalInterface(
                    name = iface.name ?: continue,
                    ip = addr.hostAddress ?: continue,
                    prefixBits = ifAddr.networkPrefixLength.toInt(),
                ))
            }
        }
    } catch (_: Throwable) {
        return emptyList()
    }
    return out
}
