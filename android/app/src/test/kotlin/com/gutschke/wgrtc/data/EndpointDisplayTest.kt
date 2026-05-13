package com.gutschke.wgrtc.data

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class ParseEndpointTest {

    @Test fun `parses plain IPv4`() {
        val r = parseEndpoint("1.2.3.4:51820")
        assertEquals("1.2.3.4" to 51820, r)
    }

    @Test fun `parses bracketed IPv6`() {
        val r = parseEndpoint("[2001:db8::1]:51820")
        assertEquals("2001:db8::1" to 51820, r)
    }

    @Test fun `parses hostname`() {
        val r = parseEndpoint("vpn.example.com:51820")
        assertEquals("vpn.example.com" to 51820, r)
    }

    @Test fun `trims whitespace`() {
        val r = parseEndpoint(" 1.2.3.4:51820 ")
        assertEquals("1.2.3.4" to 51820, r)
    }

    @Test fun `null on missing port`() {
        assertNull(parseEndpoint("1.2.3.4"))
    }

    @Test fun `null on non-numeric port`() {
        assertNull(parseEndpoint("1.2.3.4:abcd"))
    }

    @Test fun `null on empty string`() {
        assertNull(parseEndpoint(""))
        assertNull(parseEndpoint(" "))
    }

    @Test fun `null on bracketed missing port`() {
        // `[2001:db8::1]` without `:port` is rejected.
        assertNull(parseEndpoint("[2001:db8::1]"))
    }

    @Test fun `null on bracketed missing close-bracket`() {
        assertNull(parseEndpoint("[2001:db8::1:51820"))
    }

    @Test fun `last colon wins for v4 and hostname (no false IPv6 split)`() {
        // Hostnames can't legally contain colons, so taking lastIndexOf
        // is unambiguous for non-bracketed input. Sanity check.
        val r = parseEndpoint("a-b-c:1234")
        assertEquals("a-b-c" to 1234, r)
    }
}

class FormatHandshakeAgoTest {
    private val now = 1_700_000_000_000L // 2023-11-14T22:13:20Z, fixed for determinism

    @Test fun `null input renders never`() {
        assertEquals("never", formatHandshakeAgo(null, nowMs = now))
    }

    @Test fun `zero (kernel-no-handshake-yet) renders never`() {
        assertEquals("never", formatHandshakeAgo(0L, nowMs = now))
    }

    @Test fun `seconds-ago shape`() {
        assertEquals("12s ago", formatHandshakeAgo(now - 12_000, nowMs = now))
        assertEquals("0s ago", formatHandshakeAgo(now, nowMs = now))
        assertEquals("59s ago", formatHandshakeAgo(now - 59_000, nowMs = now))
    }

    @Test fun `minutes-and-seconds shape`() {
        assertEquals("1m 0s ago", formatHandshakeAgo(now - 60_000, nowMs = now))
        assertEquals("2m 45s ago", formatHandshakeAgo(now - 165_000, nowMs = now))
        assertEquals("59m 59s ago", formatHandshakeAgo(now - 3_599_000, nowMs = now))
    }

    @Test fun `hours-and-minutes shape`() {
        assertEquals("1h 0m ago", formatHandshakeAgo(now - 3_600_000, nowMs = now))
        assertEquals("3h 15m ago", formatHandshakeAgo(now - (3*3600+15*60)*1000L, nowMs = now))
    }

    @Test fun `days-and-hours shape`() {
        assertEquals("1d 0h ago", formatHandshakeAgo(now - 86_400_000L, nowMs = now))
        assertEquals("7d 12h ago",
            formatHandshakeAgo(now - (7L*86400 + 12*3600) * 1000, nowMs = now))
    }

    @Test fun `future timestamp clamps to zero (clock skew defense)`() {
        // If the kernel hands us a "handshake in the future" (clock
        // skew, NTP step, ...), don't render a negative value.
        assertEquals("0s ago", formatHandshakeAgo(now + 5_000, nowMs = now))
    }
}

class FormatBytesTest {
    // Verifies the byte-precision thresholds that let the status panel
    // tick visibly under low-bandwidth flows like the FGS demo's ping
    // stream. See [formatBytes] doc for the policy.

    @Test fun `under 100 KB shows raw bytes with thousands separator`() {
        assertEquals("0 B", formatBytes(0))
        assertEquals("84 B", formatBytes(84))
        assertEquals("999 B", formatBytes(999))
        assertEquals("1,234 B", formatBytes(1_234))
        assertEquals("99,999 B", formatBytes(99_999))
    }

    @Test fun `100 KB up to 100 MB shows KB`() {
        assertEquals("100 KB", formatBytes(100_000))
        assertEquals("1,234 KB", formatBytes(1_234_000))
        assertEquals("99,999 KB", formatBytes(99_999_000))
    }

    @Test fun `100 MB up to 1 GB shows MB with one decimal`() {
        assertEquals("100.0 MB", formatBytes(100_000_000))
        assertEquals("500.5 MB", formatBytes(500_500_000))
    }

    @Test fun `1 GB up to 100 GB shows MB (whole)`() {
        assertEquals("1,000 MB", formatBytes(1_000_000_000))
        assertEquals("12,345 MB", formatBytes(12_345_000_000))
    }

    @Test fun `over 100 GB shows GB with one decimal`() {
        assertEquals("100.0 GB", formatBytes(100_000_000_000))
        assertEquals("1234.5 GB", formatBytes(1_234_500_000_000))
    }
}

class FormatRateTest {
    @Test fun `low rates render in raw bytes per second`() {
        assertEquals("0 B/s", formatRate(0.0))
        assertEquals("84 B/s", formatRate(84.3))
        assertEquals("9,999 B/s", formatRate(9_999.0))
    }

    @Test fun `mid rates render as KB per second`() {
        assertEquals("10 KB/s", formatRate(10_000.0))
        assertEquals("1,234 KB/s", formatRate(1_234_000.0))
    }

    @Test fun `high rates render as MB per second`() {
        assertEquals("10.0 MB/s", formatRate(10_000_000.0))
        assertEquals("100.0 MB/s", formatRate(100_000_000.0))
    }
}
