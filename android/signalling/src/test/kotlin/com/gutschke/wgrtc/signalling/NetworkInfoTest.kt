package com.gutschke.wgrtc.signalling

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test

/**
 * Unit tests for the pure address-manipulation helpers used by
 * NetworkInfo.kt's ISP lookup path.  The DoH-fetching parts are
 * network I/O and aren't tested here; they're best-effort UI sugar
 * that the Settings panel surfaces opportunistically.
 */
class NetworkInfoTest {

    // ─── reverseIp4 ─────────────────────────────────────────────────────

    @Test fun `reverseIp4 reverses a typical address`() {
        assertEquals("4.3.2.1", reverseIp4("1.2.3.4"))
    }

    @Test fun `reverseIp4 handles boundary values`() {
        assertEquals("255.0.0.0", reverseIp4("0.0.0.255"))
        assertEquals("1.0.0.10", reverseIp4("10.0.0.1"))
    }

    @Test fun `reverseIp4 rejects malformed input`() {
        assertNull(reverseIp4("1.2.3"))
        assertNull(reverseIp4("1.2.3.4.5"))
        assertNull(reverseIp4("1.2.3.300"))
        assertNull(reverseIp4("a.b.c.d"))
        assertNull(reverseIp4(""))
        assertNull(reverseIp4("1.2..4"))
    }

    // ─── reverseIp6Nibbles ─────────────────────────────────────────────

    @Test fun `reverseIp6Nibbles expands and reverses 2001 db8 1`() {
        // 2001:db8::1 → expand → 20010db8000000000000000000000001
        // reverse-nibble → 1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2
        val out = reverseIp6Nibbles("2001:db8::1")
        assertEquals(
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2",
            out)
    }

    @Test fun `reverseIp6Nibbles handles loopback`() {
        // ::1 → all zeros except last byte=0x01
        val out = reverseIp6Nibbles("::1")
        assertEquals(
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0",
            out)
    }

    @Test fun `reverseIp6Nibbles handles unique-local`() {
        // fd12:3456::1 → fd 12 34 56 00 00 ... 00 01
        val out = reverseIp6Nibbles("fd12:3456::1")
        assertEquals(
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.6.5.4.3.2.1.d.f",
            out)
    }

    @Test fun `reverseIp6Nibbles rejects non-ipv6`() {
        assertNull(reverseIp6Nibbles("1.2.3.4"))
        assertNull(reverseIp6Nibbles(""))
        assertNull(reverseIp6Nibbles("not an address"))
    }
}
