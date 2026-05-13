package com.gutschke.wgrtc.signalling

import java.net.InetAddress

/**
 * Tiny CIDR utility — used by:
 *
 * - Step A (bootstrap-deadlock check): reject candidate IPs that fall
 * inside the tunnel's `[Peer] AllowedIPs`. See
 * `` §"Receiver
 * rules / Bootstrap deadlock".
 * - Step D (same-subnet override): match candidate IPs against the
 * receiver's local interface networks for the hotspot guarantee.
 *
 * Pure-JVM, no Android deps. Family-agnostic — handles v4 and v6
 * uniformly via `InetAddress.address` byte arrays.
 */

/** Parse one CIDR string into `(network_bytes, prefix_bits)` or null on
 * malformed input. Bare addresses without a prefix are interpreted
 * as `/32` (IPv4) or `/128` (IPv6) — matches `wg-quick`'s tolerance
 * of either form in `AllowedIPs`. */
internal fun parseCidr(s: String): Pair<ByteArray, Int>? {
    val trimmed = s.trim()
    if (trimmed.isEmpty()) return null
    val (host, prefixStr) = if ("/" in trimmed) {
        val parts = trimmed.split("/", limit = 2)
        parts[0] to parts[1]
    } else {
        // Bare IP — implicit host route.
        trimmed to null
    }
    // Strict literal-only check. `InetAddress.getByName` would happily
    // resolve "not-an-ip" via DNS — disastrous for an AllowedIPs parser
    // (and a denial-of-service vector if a malicious sender plants one
    // in a candidate field that ever reaches here).
    if (!IP_LITERAL_REGEX.matches(host)) return null
    val addr = try { InetAddress.getByName(host) }
               catch (_: Exception) { return null }
    val bytes = addr.address
    val prefix = when {
        prefixStr == null -> bytes.size * 8
        else -> prefixStr.toIntOrNull() ?: return null
    }
    if (prefix < 0 || prefix > bytes.size * 8) return null
    return bytes to prefix
}

/** Cheap "is this a literal IP" gate: dotted-quad v4 or hex+colon v6.
 * False positives get filtered by `getByName`'s parse below; this
 * regex's only job is to short-circuit the name-resolution path so
 * garbage like "not-an-ip" never goes near DNS. */
private val IP_LITERAL_REGEX = Regex(
    """^(\d{1,3}(\.\d{1,3}){3}|[0-9a-fA-F:]+)$"""
)

/** Does the network (`netBytes`/`prefixBits`) contain `candidateBytes`?
 * Both must be the same family (4 bytes for v4, 16 for v6); mismatched
 * families return false (a v4 candidate is never inside a v6 network
 * and vice-versa). */
internal fun cidrContains(
    netBytes: ByteArray, prefixBits: Int, candidateBytes: ByteArray,
): Boolean {
    if (netBytes.size != candidateBytes.size) return false
    val fullBytes = prefixBits / 8
    val partialBits = prefixBits % 8
    for (i in 0 until fullBytes) {
        if (netBytes[i] != candidateBytes[i]) return false
    }
    if (partialBits > 0 && fullBytes < netBytes.size) {
        val mask = (0xFF shl (8 - partialBits)) and 0xFF
        val a = netBytes[fullBytes].toInt() and mask
        val b = candidateBytes[fullBytes].toInt() and mask
        if (a != b) return false
    }
    return true
}

/** True if [ip] (literal IPv4 or IPv6 string) falls inside any of the
 * CIDR strings in [cidrs]. Empty list → false. Malformed entries
 * in [cidrs] are silently skipped — the caller pre-parsed from a
 * user-supplied `AllowedIPs` line and we don't want a stray comma to
 * disable the whole check. */
fun isInAnyCidr(ip: String, cidrs: List<String>): Boolean {
    if (cidrs.isEmpty()) return false
    if (!IP_LITERAL_REGEX.matches(ip)) return false
    val candidate = try { InetAddress.getByName(ip).address }
                    catch (_: Exception) { return false }
    for (c in cidrs) {
        val parsed = parseCidr(c) ?: continue
        if (cidrContains(parsed.first, parsed.second, candidate)) return true
    }
    return false
}

/** True iff CIDRs `a` and `b` cover any overlapping address.  Both
 * must be the same address family; mixed v4/v6 always returns false.
 * Equivalent to "the shorter-prefix range contains the longer-prefix
 * range's network address".  Used by the multi-tunnel AllowedIPs
 * overlap gate. */
internal fun cidrPairOverlaps(
    aNet: ByteArray, aPrefix: Int,
    bNet: ByteArray, bPrefix: Int,
): Boolean {
    if (aNet.size != bNet.size) return false
    return if (aPrefix <= bPrefix) cidrContains(aNet, aPrefix, bNet)
    else cidrContains(bNet, bPrefix, aNet)
}

/** True iff any CIDR in [a] overlaps any CIDR in [b].  Malformed
 * entries on either side are silently skipped (same contract as
 * [isInAnyCidr]).  Order of arguments doesn't matter — the relation
 * is symmetric. */
fun cidrsOverlap(a: List<String>, b: List<String>): Boolean {
    if (a.isEmpty() || b.isEmpty()) return false
    for (x in a) {
        val px = parseCidr(x) ?: continue
        for (y in b) {
            val py = parseCidr(y) ?: continue
            if (cidrPairOverlaps(px.first, px.second, py.first, py.second)) {
                return true
            }
        }
    }
    return false
}

/**
 * Extract every `AllowedIPs = a/n, b/m, ...` value from a wg-quick
 * config block, returning a flat list of CIDR strings. Multiple
 * `AllowedIPs` lines (legal in wg-quick) are unioned. Bare IPs
 * without a prefix are normalised to `/32` (v4) / `/128` (v6).
 *
 * Used by the receiver to compute "what address ranges am I committed
 * to routing through this tunnel" — any candidate IP inside that set
 * is a bootstrap-deadlock waiting to happen and gets rejected.
 */
fun parseAllowedIps(configText: String): List<String> {
    val out = mutableListOf<String>()
    for (line in configText.lines()) {
        val trimmed = line.trim()
        if (!trimmed.startsWith("AllowedIPs", ignoreCase = true)) continue
        if (!trimmed.contains("=")) continue
        val rhs = trimmed.substringAfter("=").trim()
        for (entry in rhs.split(",")) {
            val e = entry.trim()
            if (e.isEmpty()) continue
            val normalised = if ("/" in e) e else {
                if (":" in e) "$e/128" else "$e/32"
            }
            // Validate by parsing — keep only well-formed CIDRs.
            if (parseCidr(normalised) != null) out.add(normalised)
        }
    }
    return out
}
