package com.gutschke.wgrtc.signalling

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class EndpointFormatTest {

    @Test fun `v4 literal is rendered verbatim`() {
        assertEquals("1.2.3.4:51820", formatEndpoint("1.2.3.4", 51820))
        assertEquals("100.64.7.1:22111", formatEndpoint("100.64.7.1", 22111))
    }

    @Test fun `hostname is rendered verbatim (no colons)`() {
        // Hostnames carry no `:` so they trivially can't be confused
        // with bracketed v6. We don't synthesize Endpoint = lines
        // from hostnames in practice (the wg-quick paste flow does
        // that), but keep the formatter agnostic.
        assertEquals("vpn.example.com:51820", formatEndpoint("vpn.example.com", 51820))
    }

    @Test fun `v6 literal is bracketed`() {
        assertEquals(
            "[2001:db8::1]:51820",
            formatEndpoint("2001:db8::1", 51820)
        )
        // Real-world Chromebook ARC address — the case this whole
        // patch is for.
        assertEquals(
            "[2001:5a8:4cea:cc00:9854:9eff:fe81:b49b]:22111",
            formatEndpoint("2001:5a8:4cea:cc00:9854:9eff:fe81:b49b", 22111)
        )
    }

    @Test fun `already-bracketed v6 is not double-bracketed`() {
        assertEquals(
            "[2001:db8::1]:51820",
            formatEndpoint("[2001:db8::1]", 51820)
        )
    }

    @Test fun `v6 ULA gets bracketed too`() {
        assertEquals("[fd12:3456:789a::42]:51820", formatEndpoint("fd12:3456:789a::42", 51820))
    }

    @Test fun `surrounding whitespace is trimmed`() {
        assertEquals("1.2.3.4:51820", formatEndpoint(" 1.2.3.4 ", 51820))
        assertEquals("[2001:db8::1]:51820", formatEndpoint(" 2001:db8::1 ", 51820))
    }
}
