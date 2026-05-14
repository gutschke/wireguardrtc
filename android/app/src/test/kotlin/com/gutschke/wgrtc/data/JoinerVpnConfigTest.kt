package com.gutschke.wgrtc.data

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import java.util.Base64

/**
 * Behavior of [JoinerVpnConfig.parse] — extracts the bits a
 * `VpnService.Builder` needs from a wg-quick `.conf` text:
 *
 * - Local address(es) for `addAddress(...)` (from `[Interface]
 * Address`).
 * - Routes for `addRoute(...)` (from each `[Peer] AllowedIPs`).
 * - MTU (from `[Interface] MTU`, default 1420).
 *
 * The wg-quick → UAPI conversion is [WgQuickUapi]'s job; this
 * parser is a separate concern (Builder needs CIDRs, UAPI needs
 * hex keys; rendering both from one walk would conflate them).
 */
class JoinerVpnConfigTest {

    private val privKey = ByteArray(32) { (it + 1).toByte() }
    private val privB64 = Base64.getEncoder().encodeToString(privKey)
    private val pubB64 = Base64.getEncoder().encodeToString(ByteArray(32) { 0xAA.toByte() })

    @Test fun `single address, single AllowedIPs, default MTU`() {
        val cfg = """
            [Interface]
            PrivateKey = $privB64
            Address = 10.99.0.2/24

            [Peer]
            PublicKey = $pubB64
            AllowedIPs = 10.99.0.0/24
            Endpoint = 192.0.2.1:51820
        """.trimIndent()
        val parsed = JoinerVpnConfig.parse(cfg)
        assertEquals(listOf(Cidr("10.99.0.2", 24)), parsed.addresses)
        assertEquals(listOf(Cidr("10.99.0.0", 24)), parsed.routes)
        assertEquals(1420, parsed.mtu) // default
    }

    @Test fun `multiple Address lines yield multiple addresses`() {
        val cfg = """
            [Interface]
            PrivateKey = $privB64
            Address = 10.99.0.2/32
            Address = fd00::2/128

            [Peer]
            PublicKey = $pubB64
            AllowedIPs = 0.0.0.0/0
            Endpoint = 192.0.2.1:51820
        """.trimIndent()
        val parsed = JoinerVpnConfig.parse(cfg)
        assertEquals(2, parsed.addresses.size)
        assertEquals("10.99.0.2", parsed.addresses[0].address)
        assertEquals(32, parsed.addresses[0].prefixLen)
        assertEquals("fd00::2", parsed.addresses[1].address)
        assertEquals(128, parsed.addresses[1].prefixLen)
    }

    @Test fun `comma-separated AllowedIPs become multiple routes`() {
        val cfg = """
            [Interface]
            PrivateKey = $privB64
            Address = 10.99.0.2/24

            [Peer]
            PublicKey = $pubB64
            AllowedIPs = 10.99.0.0/24, 192.168.42.0/24, 198.51.100.0/16
            Endpoint = 192.0.2.1:51820
        """.trimIndent()
        val parsed = JoinerVpnConfig.parse(cfg)
        assertEquals(3, parsed.routes.size)
        assertEquals("10.99.0.0", parsed.routes[0].address)
        assertEquals(24, parsed.routes[0].prefixLen)
        assertEquals("192.168.42.0", parsed.routes[1].address)
        assertEquals("198.51.100.0", parsed.routes[2].address)
        assertEquals(16, parsed.routes[2].prefixLen)
    }

    @Test fun `routes accumulate across multiple Peer blocks`() {
        val pub2 = Base64.getEncoder().encodeToString(ByteArray(32) { 0xBB.toByte() })
        val cfg = """
            [Interface]
            PrivateKey = $privB64
            Address = 10.99.0.2/24

            [Peer]
            PublicKey = $pubB64
            AllowedIPs = 10.99.0.0/24
            Endpoint = 192.0.2.1:51820

            [Peer]
            PublicKey = $pub2
            AllowedIPs = 192.168.50.0/24
            Endpoint = 192.0.2.2:51820
        """.trimIndent()
        val parsed = JoinerVpnConfig.parse(cfg)
        assertEquals(2, parsed.routes.size)
    }

    @Test fun `MTU line is honored`() {
        val cfg = """
            [Interface]
            PrivateKey = $privB64
            Address = 10.99.0.2/24
            MTU = 1280

            [Peer]
            PublicKey = $pubB64
            AllowedIPs = 0.0.0.0/0
            Endpoint = 192.0.2.1:51820
        """.trimIndent()
        val parsed = JoinerVpnConfig.parse(cfg)
        assertEquals(1280, parsed.mtu)
    }

    @Test fun `bare IP without prefix defaults to 32 (v4) or 128 (v6)`() {
        // Some users write `Address = 10.99.0.2` without /32. Be
        // tolerant — treat as host-route.
        val cfg = """
            [Interface]
            PrivateKey = $privB64
            Address = 10.99.0.2

            [Peer]
            PublicKey = $pubB64
            AllowedIPs = 0.0.0.0/0
            Endpoint = 192.0.2.1:51820
        """.trimIndent()
        val parsed = JoinerVpnConfig.parse(cfg)
        assertEquals(32, parsed.addresses.single().prefixLen)
    }

    @Test fun `missing Address is an error`() {
        val cfg = """
            [Interface]
            PrivateKey = $privB64

            [Peer]
            PublicKey = $pubB64
            AllowedIPs = 0.0.0.0/0
            Endpoint = 192.0.2.1:51820
        """.trimIndent()
        assertThrows(IllegalArgumentException::class.java) {
            JoinerVpnConfig.parse(cfg)
        }
    }

    @Test fun `0_0_0_0_0 catchall route is preserved verbatim`() {
        // Full-tunnel VPN client: AllowedIPs = 0.0.0.0/0. Builder
        // will route everything through the TUN.
        val cfg = """
            [Interface]
            PrivateKey = $privB64
            Address = 10.99.0.2/32

            [Peer]
            PublicKey = $pubB64
            AllowedIPs = 0.0.0.0/0
            Endpoint = 192.0.2.1:51820
        """.trimIndent()
        val parsed = JoinerVpnConfig.parse(cfg)
        assertEquals(Cidr("0.0.0.0", 0), parsed.routes.single())
    }

    // joiner needs DNS pushed via VpnService.Builder.addDnsServer.
    // Without it, ChromeOS's resolver has no DNS server inside the VPN
    // tunnel and the user's browser / `ping google.com` etc. all fail
    // (literal IPs still work — that's how the bug was first noticed).

    @Test fun `parses single DNS line in Interface section`() {
        val cfg = """
            [Interface]
            PrivateKey = $privB64
            Address = 10.99.0.2/32
            DNS = 10.99.0.1

            [Peer]
            PublicKey = $pubB64
            AllowedIPs = 0.0.0.0/0
            Endpoint = 192.0.2.1:51820
        """.trimIndent()
        val parsed = JoinerVpnConfig.parse(cfg)
        assertEquals(listOf("10.99.0.1"), parsed.dnsServers)
    }

    @Test fun `parses comma-separated DNS entries (v4 plus v6)`() {
        val cfg = """
            [Interface]
            PrivateKey = $privB64
            Address = 10.99.0.2/32
            DNS = 1.1.1.1, 2606:4700:4700::1111

            [Peer]
            PublicKey = $pubB64
            AllowedIPs = 0.0.0.0/0
            Endpoint = 192.0.2.1:51820
        """.trimIndent()
        val parsed = JoinerVpnConfig.parse(cfg)
        assertEquals(listOf("1.1.1.1", "2606:4700:4700::1111"), parsed.dnsServers)
    }

    @Test fun `no DNS line means empty list (back-compat)`() {
        val cfg = """
            [Interface]
            PrivateKey = $privB64
            Address = 10.99.0.2/32

            [Peer]
            PublicKey = $pubB64
            AllowedIPs = 0.0.0.0/0
            Endpoint = 192.0.2.1:51820
        """.trimIndent()
        val parsed = JoinerVpnConfig.parse(cfg)
        assertEquals(emptyList<String>(), parsed.dnsServers)
    }

    @Test fun `DNS keyword is case-insensitive (dns lowercase variant)`() {
        // wg-quick is case-insensitive on keys; mirror that.
        val cfg = """
            [Interface]
            PrivateKey = $privB64
            Address = 10.99.0.2/32
            dns = 8.8.8.8

            [Peer]
            PublicKey = $pubB64
            AllowedIPs = 0.0.0.0/0
            Endpoint = 192.0.2.1:51820
        """.trimIndent()
        val parsed = JoinerVpnConfig.parse(cfg)
        assertEquals(listOf("8.8.8.8"), parsed.dnsServers)
    }

    // V6.A2 — joiner VpnService route table for IPv6.
    //
    // When the host advertises `AllowedIPs = 0.0.0.0/0, ::/0` (the
    // dual-stack full-tunnel default), the parser MUST emit a Cidr
    // entry per family. JoinerVpnService loops over `config.routes`
    // and calls `Builder.addRoute(addr, prefixLen)` — the String/Int
    // overload accepts both v4 dotted-quads and v6 colon-hex, so the
    // joiner's TUN gets a v6 default route automatically.
    //
    // Without these tests, a future refactor of `parseCidr` could
    // accidentally drop v6 entries (split on ":" instead of "/",
    // assume bare addresses are always v4, etc.) and the regression
    // would only surface on a dual-stack handshake. The parser is
    // the single source of truth for joiner route tables.

    @Test fun `V6_A2 dual-stack full tunnel produces both v4 and v6 default routes`() {
        val cfg = """
            [Interface]
            PrivateKey = $privB64
            Address = 10.99.0.2/32

            [Peer]
            PublicKey = $pubB64
            AllowedIPs = 0.0.0.0/0, ::/0
            Endpoint = 192.0.2.1:51820
        """.trimIndent()
        val parsed = JoinerVpnConfig.parse(cfg)
        assertEquals(
            listOf(Cidr("0.0.0.0", 0), Cidr("::", 0)),
            parsed.routes,
            "AllowedIPs dual-stack must expand to two routes (preserved order)",
        )
    }

    @Test fun `V6_A2 v6-only catchall produces single colon-colon route`() {
        // v6-only joiner network: host advertises only ::/0 in
        // AllowedIPs.  Parser must produce exactly one Cidr("::", 0)
        // — no synthetic v4 entry, no dropped entry.
        val cfg = """
            [Interface]
            PrivateKey = $privB64
            Address = fd00::2/128

            [Peer]
            PublicKey = $pubB64
            AllowedIPs = ::/0
            Endpoint = [2001:db8::1]:51820
        """.trimIndent()
        val parsed = JoinerVpnConfig.parse(cfg)
        assertEquals(listOf(Cidr("::", 0)), parsed.routes)
    }

    @Test fun `V6_A2 bare v6 host address defaults to slash-128`() {
        // The existing v4 test (`bare IP without prefix defaults to
        // 32 (v4) or 128 (v6)`) covers /128 for [Interface] Address;
        // this test pins the same behaviour for [Peer] AllowedIPs so
        // a refactor that touches one branch can't desync the other.
        val cfg = """
            [Interface]
            PrivateKey = $privB64
            Address = fd00::2/128

            [Peer]
            PublicKey = $pubB64
            AllowedIPs = fd00::1
            Endpoint = [2001:db8::1]:51820
        """.trimIndent()
        val parsed = JoinerVpnConfig.parse(cfg)
        assertEquals(listOf(Cidr("fd00::1", 128)), parsed.routes)
    }

    @Test fun `V6_A2 mixed v4 v6 sub-CIDR list preserves order and family`() {
        // Real-world phone-host advertising one tunnel-local subnet
        // per family plus a v6 ULA range.  Order must be preserved
        // — Builder.addRoute is order-sensitive (later wider routes
        // override earlier narrower ones in some pathological cases,
        // and we want to honor the host's intent verbatim).
        val cfg = """
            [Interface]
            PrivateKey = $privB64
            Address = 10.99.0.2/32

            [Peer]
            PublicKey = $pubB64
            AllowedIPs = 10.99.0.0/24, fd00:dead:beef::/48, 192.168.42.0/24, 2001:db8::/32
            Endpoint = 192.0.2.1:51820
        """.trimIndent()
        val parsed = JoinerVpnConfig.parse(cfg)
        assertEquals(4, parsed.routes.size)
        assertEquals(Cidr("10.99.0.0", 24), parsed.routes[0])
        assertEquals(Cidr("fd00:dead:beef::", 48), parsed.routes[1])
        assertEquals(Cidr("192.168.42.0", 24), parsed.routes[2])
        assertEquals(Cidr("2001:db8::", 32), parsed.routes[3])
    }

    @Test fun `V6_A2 v6 with zero prefix is preserved verbatim (not promoted to slash-128)`() {
        // Defensive: an explicit `/0` must stay `/0`. The parseCidr
        // branch that defaults bare addresses to /128 must not run
        // when the slash is present.
        val cfg = """
            [Interface]
            PrivateKey = $privB64
            Address = fd00::2/128

            [Peer]
            PublicKey = $pubB64
            AllowedIPs = ::/0
            Endpoint = [2001:db8::1]:51820
        """.trimIndent()
        val parsed = JoinerVpnConfig.parse(cfg)
        assertEquals(0, parsed.routes.single().prefixLen)
        assertEquals("::", parsed.routes.single().address)
    }

    @Test fun `V6_A2 v6 Address line on Interface section survives parse`() {
        // Companion to the AllowedIPs tests: the joiner needs a v6
        // local address on its TUN before any v6 route is useful.
        // Pin that the [Interface] Address branch handles v6
        // identically to v4.
        val cfg = """
            [Interface]
            PrivateKey = $privB64
            Address = fd00::2/128

            [Peer]
            PublicKey = $pubB64
            AllowedIPs = ::/0
            Endpoint = [2001:db8::1]:51820
        """.trimIndent()
        val parsed = JoinerVpnConfig.parse(cfg)
        assertEquals(listOf(Cidr("fd00::2", 128)), parsed.addresses)
    }
}
