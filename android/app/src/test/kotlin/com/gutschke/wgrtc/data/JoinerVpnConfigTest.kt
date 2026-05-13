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
}
