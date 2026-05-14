package com.gutschke.wgrtc.signalling

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * V6.A1 — happy-eyeballs preference for the joiner's enrollment
 * config renderer.  Per RFC 8305, when the host advertises both v4
 * and v6 candidates within the same rank tier (kind), the joiner
 * should prefer v6 because:
 *
 *   - IPv6 typically doesn't NAT, so the handshake racer needs no
 *     pinhole keepalive (V6.D5 already gates that on the daemon
 *     side).
 *   - On dual-stack joiner networks, v6 paths usually have lower
 *     latency than v4-via-NAT44/CGNAT.
 *
 * Across different kinds, the host's rank order is authoritative:
 *   a v6 "lan" candidate is NOT routable from outside the host's
 *   LAN, so a v4 "stun" public candidate must beat it.  Only
 *   *within the same kind* do we promote v6.
 *
 * Pure-JVM unit tests; the rank function is a stable sort over an
 * opaque candidate list.
 */
class CandidateRankV6Test {

    private fun c(ip: String, kind: String? = null, port: Int = 51820) =
        EndpointCandidate(ip = ip, port = port, kind = kind)

    @Test
    fun `empty list stays empty`() {
        assertEquals(emptyList<EndpointCandidate>(),
                     preferV6WithinKind(emptyList()))
    }

    @Test
    fun `v4-only list is unchanged`() {
        val input = listOf(
            c("203.0.113.5", "stun"),
            c("10.0.0.1",    "lan"),
        )
        assertEquals(input, preferV6WithinKind(input))
    }

    @Test
    fun `v6-only list is unchanged`() {
        val input = listOf(
            c("2001:db8::5", "stun"),
            c("fd00::1",     "lan"),
        )
        assertEquals(input, preferV6WithinKind(input))
    }

    @Test
    fun `mixed within same kind promotes v6 to the front`() {
        val input = listOf(
            c("203.0.113.5", "stun"),     // v4 first
            c("2001:db8::5", "stun"),     // v6 second
        )
        val out = preferV6WithinKind(input)
        assertEquals("2001:db8::5", out[0].ip,
            "v6 should win within the 'stun' kind; got order " +
            out.map { it.ip })
        assertEquals("203.0.113.5", out[1].ip)
    }

    @Test
    fun `kind order is preserved across families`() {
        // 'stun' (public-routable) ranked first by host;
        // 'lan' (LAN-routable only) ranked second.
        // Even when the lan entry is v6 (ULA), the stun v4 must
        // still come first — v6 ULA isn't reachable from outside
        // the host's LAN, so the joiner can't use it from across
        // the internet.
        val input = listOf(
            c("203.0.113.5", "stun"),   // v4 public
            c("fd00::1",     "lan"),    // v6 ULA
        )
        val out = preferV6WithinKind(input)
        assertEquals("203.0.113.5", out[0].ip,
            "public v4 should beat ULA v6 across different kinds")
        assertEquals("fd00::1", out[1].ip)
    }

    @Test
    fun `multiple entries per kind preserve original v6-then-v4 sub-order`() {
        // Host advertises two v4 and two v6 entries in the 'stun'
        // kind plus one v4 LAN.  v6's go to the front of stun in
        // original relative order, then v4's of stun, then lan.
        val input = listOf(
            c("203.0.113.5",  "stun"),   // v4 stun #1
            c("2001:db8::1",  "stun"),   // v6 stun #1
            c("203.0.113.6",  "stun"),   // v4 stun #2
            c("2001:db8::2",  "stun"),   // v6 stun #2
            c("192.168.1.1",  "lan"),    // v4 lan
        )
        val out = preferV6WithinKind(input)
        assertEquals(
            listOf(
                "2001:db8::1",  // v6 stun, relative order kept
                "2001:db8::2",
                "203.0.113.5",  // v4 stun, relative order kept
                "203.0.113.6",
                "192.168.1.1",  // lan unchanged (only v4 there)
            ),
            out.map { it.ip },
        )
    }

    @Test
    fun `null kind treated as its own implicit tier`() {
        // Older daemons (pre-V6.D3) may omit the kind field.  We
        // treat null as a single tier; v6 still promotes to front
        // within that tier.
        val input = listOf(
            c("203.0.113.5"),    // v4, kind=null
            c("2001:db8::5"),    // v6, kind=null
        )
        val out = preferV6WithinKind(input)
        assertEquals("2001:db8::5", out[0].ip)
        assertEquals("203.0.113.5", out[1].ip)
    }

    @Test
    fun `null kind tier is distinct from named kind tier`() {
        // If the host advertises both null-kind and named-kind
        // entries (mixed-version daemon-app combo), we keep the
        // host's original tier order.  Null comes first because
        // it appeared first.
        val input = listOf(
            c("203.0.113.5"),               // v4, kind=null  (tier 1)
            c("2001:db8::5", "stun"),       // v6, kind=stun  (tier 2)
            c("10.0.0.1",    "lan"),        // v4, kind=lan   (tier 3)
        )
        val out = preferV6WithinKind(input)
        // No swaps within any tier (each has one entry).  Order
        // preserved.
        assertEquals(input, out)
    }

    @Test
    fun `port and other fields are preserved through the sort`() {
        val input = listOf(
            c("203.0.113.5", "stun", port = 4567),
            c("2001:db8::5", "stun", port = 8901),
        )
        val out = preferV6WithinKind(input)
        assertEquals(8901, out[0].port,
            "port must follow the candidate it belongs to")
        assertEquals(4567, out[1].port)
    }

    @Test
    fun `malformed ip strings are treated as v4 family (preserve relative order)`() {
        // Defensive: a corrupted candidate string shouldn't crash
        // the sort.  Anything without a colon counts as 'not v6'
        // and stays where it was.
        val input = listOf(
            c("not-an-ip",      "stun"),
            c("2001:db8::5",    "stun"),
        )
        val out = preferV6WithinKind(input)
        assertEquals("2001:db8::5", out[0].ip)
        assertEquals("not-an-ip",   out[1].ip)
    }
}
