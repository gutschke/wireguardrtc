package com.gutschke.wgrtc.data

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

/**
 * V6.H1 — pull every `[Interface] Address = …` entry out of a
 * wg-quick config, tolerating both multi-line and comma-separated
 * forms, and strip the `/prefix` suffix so what's left is bare
 * IPv4 or IPv6 literals suitable for `wgbridgeNew`.
 *
 * The pre-V6 path used `parseInterfaceField(text, "Address")` which
 * returned only the FIRST line's value verbatim — including the
 * `/24` prefix — and the caller stripped via `substringBefore('/')`.
 * That worked for `Address = 10.99.0.1/24` but silently dropped:
 *
 *   - A second Address line for v6 (`Address = fd00::1/64`).
 *   - A comma-separated single-line dual-stack
 *     (`Address = 10.99.0.1/24, fd00::1/64`).
 *
 * `parseInterfaceAddresses` returns every bare address so the
 * caller can feed `10.99.0.1,fd00::1` to the wgbridge_native
 * dual-stack-aware `parseLocalAddrs`.
 */
class ParseInterfaceAddressesTest {

    @Test fun `single v4 Address line`() {
        val cfg = """
            [Interface]
            PrivateKey = abc=
            Address = 10.99.0.1/24
            ListenPort = 51820
        """.trimIndent()
        assertEquals(listOf("10.99.0.1"), parseInterfaceAddresses(cfg))
    }

    @Test fun `multiple Address lines preserved in order`() {
        val cfg = """
            [Interface]
            PrivateKey = abc=
            Address = 10.99.0.1/24
            Address = fd00::1/64
            ListenPort = 51820
        """.trimIndent()
        assertEquals(listOf("10.99.0.1", "fd00::1"), parseInterfaceAddresses(cfg))
    }

    @Test fun `comma-separated single line is split`() {
        val cfg = """
            [Interface]
            PrivateKey = abc=
            Address = 10.99.0.1/24, fd00::1/64
            ListenPort = 51820
        """.trimIndent()
        assertEquals(listOf("10.99.0.1", "fd00::1"), parseInterfaceAddresses(cfg))
    }

    @Test fun `combination of multi-line and comma-separated`() {
        val cfg = """
            [Interface]
            PrivateKey = abc=
            Address = 10.99.0.1/24, 192.168.42.1/24
            Address = fd00::1/64
            ListenPort = 51820
        """.trimIndent()
        assertEquals(
            listOf("10.99.0.1", "192.168.42.1", "fd00::1"),
            parseInterfaceAddresses(cfg),
        )
    }

    @Test fun `bare v4 without prefix is preserved`() {
        // Some operators omit `/32` for host-routes.
        val cfg = """
            [Interface]
            PrivateKey = abc=
            Address = 10.99.0.1
        """.trimIndent()
        assertEquals(listOf("10.99.0.1"), parseInterfaceAddresses(cfg))
    }

    @Test fun `bare v6 without prefix is preserved`() {
        val cfg = """
            [Interface]
            PrivateKey = abc=
            Address = fd00::1
        """.trimIndent()
        assertEquals(listOf("fd00::1"), parseInterfaceAddresses(cfg))
    }

    @Test fun `no Address line returns empty list`() {
        val cfg = """
            [Interface]
            PrivateKey = abc=
            ListenPort = 51820
        """.trimIndent()
        assertEquals(emptyList<String>(), parseInterfaceAddresses(cfg))
    }

    @Test fun `Address lines outside Interface section are ignored`() {
        // wg-quick treats `Address = ...` outside [Interface] as
        // either a parse error or no-op depending on impl; we
        // mirror parseInterfaceField's section-tracking behavior.
        val cfg = """
            [Interface]
            PrivateKey = abc=
            Address = 10.99.0.1/24

            [Peer]
            PublicKey = def=
            Address = 192.168.99.1/32
        """.trimIndent()
        // Only the [Interface] entry should survive.
        assertEquals(listOf("10.99.0.1"), parseInterfaceAddresses(cfg))
    }

    @Test fun `case-insensitive Address key`() {
        val cfg = """
            [Interface]
            PrivateKey = abc=
            address = 10.99.0.1/24
        """.trimIndent()
        assertEquals(listOf("10.99.0.1"), parseInterfaceAddresses(cfg))
    }

    @Test fun `comments after Address line are ignored`() {
        // wg-quick comments start with `#`.
        val cfg = """
            [Interface]
            PrivateKey = abc=
            Address = 10.99.0.1/24  # site internal
            Address = fd00::1/64
        """.trimIndent()
        assertEquals(listOf("10.99.0.1", "fd00::1"), parseInterfaceAddresses(cfg))
    }

    @Test fun `empty Address segments dropped`() {
        // Defensive: `Address = ,10.99.0.1/24,` should still yield
        // a single entry; double-commas are tolerated.
        val cfg = """
            [Interface]
            PrivateKey = abc=
            Address = ,10.99.0.1/24,,fd00::1/64,
        """.trimIndent()
        assertEquals(listOf("10.99.0.1", "fd00::1"), parseInterfaceAddresses(cfg))
    }
}
