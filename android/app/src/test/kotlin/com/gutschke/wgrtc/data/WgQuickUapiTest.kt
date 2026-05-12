package com.gutschke.wgrtc.data

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.util.Base64

/**
 * Behaviour of [WgQuickUapi]: parses joiner-side wg-quick text and
 * emits the UAPI string wireguard-go's IpcSet expects. Mirrors the
 * format wireguard-android's `Config.parse(...)` + `getStatistics`
 * dance produced — once drops that dependency, this is the
 * only path from wg-quick → UAPI in the app, so the conversion
 * needs to be airtight.
 */
class WgQuickUapiTest {

    private val privKey = ByteArray(32) { (it + 1).toByte() }
    private val privB64 = Base64.getEncoder().encodeToString(privKey)
    private val privHex = privKey.joinToString("") { "%02x".format(it) }
    private val pubKey = ByteArray(32) { 0xAA.toByte() }
    private val pubB64 = Base64.getEncoder().encodeToString(pubKey)
    private val pubHex = "aa".repeat(32)

    @Test fun `joiner config with one peer, endpoint, keepalive`() {
        val cfg = """
            [Interface]
            PrivateKey = $privB64
            Address = 10.99.0.2/32

            [Peer]
            PublicKey = $pubB64
            AllowedIPs = 10.99.0.0/24
            Endpoint = 192.0.2.1:51820
            PersistentKeepalive = 25
        """.trimIndent()
        val uapi = WgQuickUapi.render(cfg)
        // private_key first, then per-peer block.
        val expected = """
            private_key=$privHex
            replace_peers=true
            public_key=$pubHex
            endpoint=192.0.2.1:51820
            persistent_keepalive_interval=25
            replace_allowed_ips=true
            allowed_ip=10.99.0.0/24
        """.trimIndent() + "\n"
        assertEquals(expected, uapi)
    }

    @Test fun `joiner config without keepalive omits the line`() {
        val cfg = """
            [Interface]
            PrivateKey = $privB64
            Address = 10.99.0.2/32

            [Peer]
            PublicKey = $pubB64
            AllowedIPs = 0.0.0.0/0
            Endpoint = 192.0.2.1:51820
        """.trimIndent()
        val uapi = WgQuickUapi.render(cfg)
        assertTrue(uapi.contains("endpoint=192.0.2.1:51820"))
        assertTrue(!uapi.contains("persistent_keepalive_interval"),
            "no keepalive line expected when [Peer] doesn't set one:\n$uapi")
    }

    @Test fun `multiple AllowedIPs become multiple allowed_ip lines`() {
        val cfg = """
            [Interface]
            PrivateKey = $privB64

            [Peer]
            PublicKey = $pubB64
            AllowedIPs = 10.99.0.0/24, 192.168.42.0/24
            Endpoint = 192.0.2.1:51820
        """.trimIndent()
        val uapi = WgQuickUapi.render(cfg)
        assertTrue(uapi.contains("allowed_ip=10.99.0.0/24"))
        assertTrue(uapi.contains("allowed_ip=192.168.42.0/24"))
    }

    @Test fun `ListenPort in Interface section is honoured`() {
        // Joiner ListenPort is uncommon (joiners pick ephemeral) but
        // some users pin it; preserve the value.
        val cfg = """
            [Interface]
            PrivateKey = $privB64
            ListenPort = 51820

            [Peer]
            PublicKey = $pubB64
            AllowedIPs = 10.0.0.1/32
            Endpoint = 192.0.2.1:51820
        """.trimIndent()
        val uapi = WgQuickUapi.render(cfg)
        assertTrue(uapi.contains("listen_port=51820"))
    }

    @Test fun `omitted ListenPort omits the UAPI line (wg-go picks ephemeral)`() {
        val cfg = """
            [Interface]
            PrivateKey = $privB64

            [Peer]
            PublicKey = $pubB64
            AllowedIPs = 10.0.0.1/32
            Endpoint = 192.0.2.1:51820
        """.trimIndent()
        val uapi = WgQuickUapi.render(cfg)
        assertTrue(!uapi.contains("listen_port"),
            "no listen_port line expected when wg-quick omits it:\n$uapi")
    }

    @Test fun `missing PrivateKey is an error — joiner cannot proceed`() {
        val cfg = """
            [Interface]
            Address = 10.99.0.2/32

            [Peer]
            PublicKey = $pubB64
            AllowedIPs = 0.0.0.0/0
            Endpoint = 192.0.2.1:51820
        """.trimIndent()
        assertThrows(IllegalArgumentException::class.java) {
            WgQuickUapi.render(cfg)
        }
    }

    @Test fun `tolerates Windows line endings + comments + blank lines`() {
        val cfg = "# header comment\r\n[Interface]\r\nPrivateKey = $privB64\r\n\r\n" +
            "[Peer]\r\n# inline comment\r\nPublicKey = $pubB64\r\n" +
            "AllowedIPs = 10.0.0.1/32\r\nEndpoint = 192.0.2.1:51820\r\n"
        val uapi = WgQuickUapi.render(cfg)
        assertTrue(uapi.contains("private_key=$privHex"))
        assertTrue(uapi.contains("public_key=$pubHex"))
        assertTrue(uapi.contains("endpoint=192.0.2.1:51820"))
    }

    @Test fun `multiple Peer blocks are emitted in order`() {
        // Most consumer-grade joiners only have one peer (the
        // server), but kernel WG accepts multiple. Round-trip the
        // ordering for parity with wg-quick semantics.
        val pub2 = Base64.getEncoder().encodeToString(ByteArray(32) { 0xBB.toByte() })
        val pub2Hex = "bb".repeat(32)
        val cfg = """
            [Interface]
            PrivateKey = $privB64

            [Peer]
            PublicKey = $pubB64
            AllowedIPs = 10.0.0.1/32
            Endpoint = 192.0.2.1:51820

            [Peer]
            PublicKey = $pub2
            AllowedIPs = 10.0.0.2/32
            Endpoint = 192.0.2.2:51820
        """.trimIndent()
        val uapi = WgQuickUapi.render(cfg)
        val firstIdx = uapi.indexOf("public_key=$pubHex")
        val secondIdx = uapi.indexOf("public_key=$pub2Hex")
        assertTrue(firstIdx > 0)
        assertTrue(secondIdx > firstIdx,
            "second peer must come after first; got firstIdx=$firstIdx secondIdx=$secondIdx")
    }

    @Test fun `replace_peers and replace_allowed_ips are present`() {
        // For revoke / reconfigure to work on the joiner side too —
        // same reasoning as for the host: merge semantics leak
        // stale peers / stale allowed_ips otherwise.
        val cfg = """
            [Interface]
            PrivateKey = $privB64

            [Peer]
            PublicKey = $pubB64
            AllowedIPs = 10.0.0.1/32
            Endpoint = 192.0.2.1:51820
        """.trimIndent()
        val uapi = WgQuickUapi.render(cfg)
        assertTrue(uapi.contains("replace_peers=true"))
        assertTrue(uapi.contains("replace_allowed_ips=true"))
    }
}
