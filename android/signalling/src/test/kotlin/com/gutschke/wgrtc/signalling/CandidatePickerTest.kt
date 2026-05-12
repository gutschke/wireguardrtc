package com.gutschke.wgrtc.signalling

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

/**
 * Receiver-side candidate picker tests (Step D-detect). Covers:
 *
 * - same-subnet detection across /24, /16, /22 (partial-byte prefix)
 * - re-ranking puts same-subnet candidates first
 * - strict-mode drops every non-same-subnet candidate (THE hotspot
 * guarantee — see project_protocol_signal_wake_candidates.md
 * §"Hotspot data-leak prevention")
 * - empty inputs / no matches degrade gracefully (no crash, no
 * surprise re-ordering)
 * - egressInterface is populated correctly for same-subnet picks
 * so Step F's bindSocket call has the right Network handle
 */
class CandidatePickerTest {

    private fun ep(ip: String, port: Int = 51820, ts: Long = 1_700_000_000L) =
        EndpointUpdate(ip = ip, port = port, ts = ts)

    private fun li(name: String, ip: String, prefix: Int) =
        LocalInterface(name, ip, prefix)

    // ─── matchSameSubnet ─────────────────────────────────────────────

    @Test fun `matchSameSubnet finds matching interface across slash 24`() {
        val ifaces = listOf(li("wlan0", "192.168.1.42", 24))
        val match = matchSameSubnet("192.168.1.1", ifaces)
        assertNotNull(match)
        assertEquals("wlan0", match!!.name)
    }

    @Test fun `matchSameSubnet returns null for out-of-subnet candidate`() {
        val ifaces = listOf(li("wlan0", "192.168.1.42", 24))
        assertNull(matchSameSubnet("192.168.2.1", ifaces))
    }

    @Test fun `matchSameSubnet uses receiver netmask not 24-default`() {
        // Receiver has /16; candidate is in the same /16 but a
        // different /24. /24 default would say "no match" —
        // wrong; the right answer is "yes match".
        val ifaces = listOf(li("wlan0", "10.42.7.5", 16))
        val match = matchSameSubnet("10.42.99.1", ifaces)
        assertNotNull(match, "wlan0 has /16, 10.42.99.1 is in 10.42/16")
    }

    @Test fun `matchSameSubnet across slash 22 partial-byte prefix`() {
        val ifaces = listOf(li("eth0", "10.0.0.1", 22))
        // /22 covers 10.0.0.0 - 10.0.3.255
        assertNotNull(matchSameSubnet("10.0.3.250", ifaces))
        assertNull(matchSameSubnet("10.0.4.1", ifaces))
    }

    @Test fun `matchSameSubnet with multiple ifaces takes first match`() {
        // Overlapping subnets — first one wins (deterministic).
        val ifaces = listOf(
            li("wlan0", "192.168.1.42", 24),
            li("eth0", "192.168.0.0", 16), // /16 covers wlan0's /24 too
        )
        val match = matchSameSubnet("192.168.1.99", ifaces)
        assertEquals("wlan0", match!!.name)
    }

    @Test fun `matchSameSubnet returns null for malformed candidate IP`() {
        val ifaces = listOf(li("wlan0", "192.168.1.1", 24))
        assertNull(matchSameSubnet("not-an-ip", ifaces))
    }

    @Test fun `matchSameSubnet returns null when ifaces list empty`() {
        assertNull(matchSameSubnet("1.2.3.4", emptyList()))
    }

    // ─── pickReceiverCandidates: ranking ─────────────────────────────

    @Test fun `pickReceiver no same-subnet preserves sender order`() {
        val candidates = listOf(ep("203.0.113.5"), ep("198.51.100.1"))
        val ifaces = listOf(li("wlan0", "10.0.0.1", 24))
        val r = pickReceiverCandidates(candidates, ifaces)
        assertEquals(2, r.size)
        assertEquals("203.0.113.5", r[0].candidate.ip)
        assertEquals("198.51.100.1", r[1].candidate.ip)
        assertFalse(r[0].isSameSubnet)
        assertFalse(r[1].isSameSubnet)
        assertNull(r[0].egressInterface)
    }

    @Test fun `pickReceiver same-subnet candidate ranks above stun`() {
        // Hotspot scenario: phone host advertises [LAN, STUN].
        // Receiver is on the hotspot LAN. LAN candidate must come
        // FIRST (its rank from the sender is 50; STUN's is 10) —
        // the receiver's same-subnet override flips that.
        val candidates = listOf(
            ep("203.0.113.5"), // STUN — sender ranked first
            ep("192.168.43.1"), // LAN — sender ranked second
        )
        val ifaces = listOf(li("wlan0", "192.168.43.42", 24))
        val r = pickReceiverCandidates(candidates, ifaces)
        assertEquals("192.168.43.1", r[0].candidate.ip)
        assertTrue(r[0].isSameSubnet)
        assertEquals("wlan0", r[0].egressInterface)
        assertEquals("203.0.113.5", r[1].candidate.ip)
        assertFalse(r[1].isSameSubnet)
    }

    @Test fun `pickReceiver multiple same-subnet candidates preserve sender order`() {
        // If sender lists [LAN_a, LAN_b, STUN] and both LANs match
        // local subnets, LAN_a comes first (sender's preference)
        // followed by LAN_b, then STUN.
        val candidates = listOf(
            ep("192.168.43.1"),
            ep("192.168.43.2"),
            ep("203.0.113.5"),
        )
        val ifaces = listOf(li("wlan0", "192.168.43.42", 24))
        val r = pickReceiverCandidates(candidates, ifaces)
        assertEquals(
            listOf("192.168.43.1", "192.168.43.2", "203.0.113.5"),
            r.map { it.candidate.ip }
        )
        assertTrue(r[0].isSameSubnet)
        assertTrue(r[1].isSameSubnet)
        assertFalse(r[2].isSameSubnet)
    }

    // ─── pickReceiverCandidates: strict-mode (THE hotspot guarantee) ──

    @Test fun `pickReceiver strict mode drops non-same-subnet when LAN match exists`() {
        // Receiver IS on the hotspot LAN. Strict mode means we
        // refuse to fall through to STUN even if LAN handshake
        // fails — better a clear error than silently billing
        // cellular data.
        val candidates = listOf(
            ep("203.0.113.5"),
            ep("192.168.43.1"),
            ep("198.51.100.1"),
        )
        val ifaces = listOf(li("wlan0", "192.168.43.42", 24))
        val r = pickReceiverCandidates(candidates, ifaces, strictHotspot = true)
        assertEquals(1, r.size, "strict mode should drop non-same-subnet")
        assertEquals("192.168.43.1", r[0].candidate.ip)
    }

    @Test fun `pickReceiver strict mode passthrough when NO same-subnet match`() {
        // Receiver is NOT on the hotspot LAN (e.g., remote peer
        // connecting via cellular). Strict mode is harmless here —
        // it only kicks in when same-subnet exists. All
        // candidates pass through unchanged.
        val candidates = listOf(ep("203.0.113.5"), ep("192.168.43.1"))
        val ifaces = listOf(li("wlan0", "10.0.0.5", 24)) // not hotspot LAN
        val r = pickReceiverCandidates(candidates, ifaces, strictHotspot = true)
        assertEquals(2, r.size)
        assertEquals(listOf("203.0.113.5", "192.168.43.1"), r.map { it.candidate.ip })
    }

    @Test fun `pickReceiver non-strict same-subnet first then fall-through`() {
        // Default (non-strict) hotspot policy: same-subnet first,
        // but if it fails the caller may try the rest.
        val candidates = listOf(ep("203.0.113.5"), ep("192.168.43.1"))
        val ifaces = listOf(li("wlan0", "192.168.43.42", 24))
        val r = pickReceiverCandidates(candidates, ifaces, strictHotspot = false)
        assertEquals(2, r.size)
        assertEquals("192.168.43.1", r[0].candidate.ip) // same-subnet first
        assertEquals("203.0.113.5", r[1].candidate.ip) // fall-through
    }

    // ─── degenerate cases ────────────────────────────────────────────

    @Test fun `pickReceiver empty candidates yields empty`() {
        val r = pickReceiverCandidates(emptyList(), emptyList())
        assertTrue(r.isEmpty())
    }

    @Test fun `pickReceiver empty interfaces yields all candidates as not-same-subnet`() {
        val candidates = listOf(ep("192.168.43.1"), ep("203.0.113.5"))
        val r = pickReceiverCandidates(candidates, emptyList())
        assertEquals(2, r.size)
        r.forEach {
            assertFalse(it.isSameSubnet)
            assertNull(it.egressInterface)
        }
    }

    // ─── egressInterface is populated correctly ──────────────────────

    @Test fun `egressInterface names the matching iface for same-subnet`() {
        // Receiver has TWO interfaces. Same-subnet match must
        // record the SPECIFIC iface (not just "yes/no") because
        // Step F's bindSocket call needs to bind to that exact
        // Network handle.
        val candidates = listOf(ep("192.168.43.1"))
        val ifaces = listOf(
            li("wlan0", "10.0.0.5", 24), // home Wi-Fi
            li("wlan2", "192.168.43.42", 24), // hotspot AP
        )
        val r = pickReceiverCandidates(candidates, ifaces)
        assertEquals("wlan2", r[0].egressInterface) // NOT wlan0
    }

    @Test fun `egressInterface null for non-same-subnet picks`() {
        val candidates = listOf(ep("203.0.113.5"))
        val ifaces = listOf(li("wlan0", "10.0.0.5", 24))
        val r = pickReceiverCandidates(candidates, ifaces)
        assertNull(r[0].egressInterface)
    }

    // ─── enumerateLocalInterfaces (smoke test) ───────────────────────

    @Test fun `enumerateLocalInterfaces returns at least loopback skipped, may be empty`() {
        // Just verify no crash + the result excludes loopback.
        // The contents are host-dependent so we can't assert exact
        // list, but we CAN assert what's NOT in it.
        val r = enumerateLocalInterfaces()
        assertTrue(r.none { it.ip == "127.0.0.1" }, "loopback must be excluded")
        // All entries must be v4 (we filter out v6 in the helper).
        r.forEach {
            val parts = it.ip.split(".")
            assertEquals(4, parts.size, "expected v4, got ${it.ip}")
        }
    }
}
