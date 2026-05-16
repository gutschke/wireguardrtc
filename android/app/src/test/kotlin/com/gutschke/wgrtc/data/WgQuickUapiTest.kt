package com.gutschke.wgrtc.data

import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.util.Base64

/**
 * Behavior of [WgQuickUapi]: parses joiner-side wg-quick text and
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

    @Test fun `joiner config without keepalive defaults to 25 when endpoint is set`() {
        // Bug: wireguard-go won't initiate a handshake until either
        // outbound traffic hits the tun or keepalive fires. The
        // candidate race only calls setEndpoint, so a peer config
        // with Endpoint but no PersistentKeepalive deadlocks the race.
        // The renderer fills in the WireGuard handbook's recommended
        // 25 s default. Enrollment-emitted configs already include
        // an explicit value; this fallback covers manually-imported
        // configs.
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
        assertTrue(uapi.contains("persistent_keepalive_interval=25"),
            "default keepalive=25 expected when peer has endpoint but no PersistentKeepalive:\n$uapi")
    }

    @Test fun `explicit PersistentKeepalive zero is preserved`() {
        // Some users explicitly disable keepalive (privacy, battery,
        // pinned-host scenarios). Honour the explicit 0 instead of
        // overwriting it with the default.
        val cfg = """
            [Interface]
            PrivateKey = $privB64

            [Peer]
            PublicKey = $pubB64
            AllowedIPs = 0.0.0.0/0
            Endpoint = 192.0.2.1:51820
            PersistentKeepalive = 0
        """.trimIndent()
        val uapi = WgQuickUapi.render(cfg)
        assertTrue(uapi.contains("persistent_keepalive_interval=0"),
            "explicit =0 must be preserved verbatim:\n$uapi")
        assertTrue(!uapi.contains("persistent_keepalive_interval=25"),
            "must NOT inject the default when an explicit value is present:\n$uapi")
    }

    @Test fun `peer with no endpoint does not gain a keepalive line`() {
        // A peer without an Endpoint is server-only (won't initiate).
        // Keepalive is pointless there — leave the line out so the
        // UAPI matches the user's intent.
        val cfg = """
            [Interface]
            PrivateKey = $privB64

            [Peer]
            PublicKey = $pubB64
            AllowedIPs = 10.0.0.0/24
        """.trimIndent()
        val uapi = WgQuickUapi.render(cfg)
        assertTrue(!uapi.contains("persistent_keepalive_interval"),
            "no keepalive expected for endpoint-less peer:\n$uapi")
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

    @Test fun `ListenPort in Interface section is honored`() {
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

    // ----- resolveEndpoints / EndpointResolver -----------------------

    /** Test resolver that returns deterministic results from a map.
     *  Throws IllegalArgumentException if the input hostPort isn't
     *  registered, so unhandled cases fail the test loudly. */
    private class FakeResolver(private val mapping: Map<String, String>) : WgQuickUapi.EndpointResolver {
        var calls: Int = 0
            private set
        override suspend fun resolve(hostPort: String): String {
            calls++
            return mapping[hostPort]
                ?: throw IllegalArgumentException("unmapped endpoint in test: '$hostPort'")
        }
    }

    @Test fun `resolveEndpoints rewrites hostname to IP literal`() = runTest {
        // The exact bug v0.2.10 hit: a wg-quick config with
        // Endpoint = host:port produces UAPI that wireguard-go's
        // IpcSet rejects ("ParseAddr: unexpected character").
        // resolveEndpoints must substitute an IP literal in place
        // before the UAPI is pushed.
        val cfg = """
            [Interface]
            PrivateKey = $privB64

            [Peer]
            PublicKey = $pubB64
            AllowedIPs = 0.0.0.0/0
            Endpoint = sonic.gutschke.com:22111
            PersistentKeepalive = 25
        """.trimIndent()
        val uapi = WgQuickUapi.render(cfg)
        val resolver = FakeResolver(mapOf(
            "sonic.gutschke.com:22111" to "203.0.113.42:22111",
        ))
        val resolved = WgQuickUapi.resolveEndpoints(uapi, resolver)
        assertTrue(
            resolved.contains("endpoint=203.0.113.42:22111"),
            "expected resolved IP in UAPI, got:\n$resolved",
        )
        assertTrue(
            !resolved.contains("sonic.gutschke.com"),
            "raw hostname should be gone from UAPI, got:\n$resolved",
        )
        assertEquals(1, resolver.calls)
    }

    @Test fun `resolveEndpoints passes IPv4 literals through unchanged`() = runTest {
        val uapi = "private_key=$privHex\n" +
                   "public_key=$pubHex\n" +
                   "endpoint=192.0.2.1:51820\n"
        val resolver = FakeResolver(mapOf(
            // SystemDnsEndpointResolver would happily echo a v4 literal back;
            // we mirror that here.
            "192.0.2.1:51820" to "192.0.2.1:51820",
        ))
        val out = WgQuickUapi.resolveEndpoints(uapi, resolver)
        assertEquals(uapi, out)
    }

    @Test fun `resolveEndpoints passes bracketed IPv6 literals through unchanged`() = runTest {
        val uapi = "private_key=$privHex\n" +
                   "public_key=$pubHex\n" +
                   "endpoint=[2001:db8::1]:51820\n"
        val resolver = FakeResolver(mapOf(
            "[2001:db8::1]:51820" to "[2001:db8::1]:51820",
        ))
        val out = WgQuickUapi.resolveEndpoints(uapi, resolver)
        assertEquals(uapi, out)
    }

    @Test fun `resolveEndpoints handles UAPI with no endpoint line`() = runTest {
        // A peer with no Endpoint (passive-only) emits no endpoint=
        // line.  resolveEndpoints must be a no-op, including not
        // invoking the resolver at all.
        val uapi = "private_key=$privHex\n" +
                   "public_key=$pubHex\n" +
                   "replace_allowed_ips=true\n" +
                   "allowed_ip=10.0.0.0/24\n"
        val resolver = FakeResolver(emptyMap())
        val out = WgQuickUapi.resolveEndpoints(uapi, resolver)
        assertEquals(uapi, out)
        assertEquals(0, resolver.calls)
    }

    @Test fun `resolveEndpoints handles multiple peers each with hostname`() = runTest {
        val cfg = """
            [Interface]
            PrivateKey = $privB64

            [Peer]
            PublicKey = $pubB64
            AllowedIPs = 10.1.0.0/24
            Endpoint = host-a.example.com:51820

            [Peer]
            PublicKey = $pubB64
            AllowedIPs = 10.2.0.0/24
            Endpoint = host-b.example.com:51821
        """.trimIndent()
        val uapi = WgQuickUapi.render(cfg)
        val resolver = FakeResolver(mapOf(
            "host-a.example.com:51820" to "203.0.113.10:51820",
            "host-b.example.com:51821" to "[2001:db8::b]:51821",
        ))
        val out = WgQuickUapi.resolveEndpoints(uapi, resolver)
        assertTrue(out.contains("endpoint=203.0.113.10:51820"))
        assertTrue(out.contains("endpoint=[2001:db8::b]:51821"))
        assertEquals(2, resolver.calls)
    }

    @Test fun `resolveEndpoints propagates resolver failure`() = runTest {
        val uapi = "endpoint=does-not-resolve.invalid:51820\n"
        val resolver = FakeResolver(emptyMap())  // any lookup throws
        val e = assertThrows(IllegalArgumentException::class.java) {
            kotlinx.coroutines.runBlocking {
                WgQuickUapi.resolveEndpoints(uapi, resolver)
            }
        }
        assertTrue(
            e.message!!.contains("does-not-resolve.invalid"),
            "expected error to mention failing host, got: ${e.message}",
        )
    }

    @Test fun `splitHostPort handles plain host port`() {
        val (host, port) = WgQuickUapi.splitHostPort("example.com:51820")
        assertEquals("example.com", host)
        assertEquals("51820", port)
    }

    @Test fun `splitHostPort handles IPv4 literal`() {
        val (host, port) = WgQuickUapi.splitHostPort("192.0.2.1:51820")
        assertEquals("192.0.2.1", host)
        assertEquals("51820", port)
    }

    @Test fun `splitHostPort handles bracketed IPv6 literal`() {
        val (host, port) = WgQuickUapi.splitHostPort("[2001:db8::1]:51820")
        assertEquals("2001:db8::1", host)
        assertEquals("51820", port)
    }

    @Test fun `splitHostPort rejects missing port`() {
        val e = assertThrows(IllegalArgumentException::class.java) {
            WgQuickUapi.splitHostPort("example.com")
        }
        assertTrue(e.message!!.contains("missing"))
    }

    @Test fun `splitHostPort rejects malformed bracketed form`() {
        val e = assertThrows(IllegalArgumentException::class.java) {
            WgQuickUapi.splitHostPort("[2001:db8::1")  // no closing bracket
        }
        assertTrue(e.message!!.contains("bracketed") || e.message!!.contains("malformed"))
    }

    @Test fun `splitHostPort rejects empty host or port`() {
        assertThrows(IllegalArgumentException::class.java) {
            WgQuickUapi.splitHostPort(":51820")
        }
        assertThrows(IllegalArgumentException::class.java) {
            WgQuickUapi.splitHostPort("host.example.com:")
        }
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
