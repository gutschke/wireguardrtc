package com.gutschke.wgrtc.signalling

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

class EnrollUriTest {

    // A representative URI shape — matches what `wireguardrtc --enroll-token`
    // emits. Server pubkey, salt, token are all 32-byte URL-safe-base64
    // values *without* padding (matches PROTOCOL §4.4.1).
    // 32-byte values, URL-safe-base64-no-padding (43 chars each), matching
    // what `wireguardrtc --enroll-token` actually emits. Generated as
    // `base64.urlsafe_b64encode(b"\x00"*32).rstrip(b"=")` etc.
    private val sampleUri = (
        "wgrtc-enroll://v1?" +
        "pk=AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA&" +
        "salt=ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8&" +
        "broker=wss%3A%2F%2Fbroker.example.org%2Fpeerjs&" +
        "brokerkey=demo&" +
        "token=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8&" +
        "expires=2000000000&" +
        "server=test-host"
    )

    @Test fun `parses all fields from a well-formed URI`() {
        val u = EnrollUri.parse(sampleUri)
        assertEquals(32, u.serverPub.size)
        assertEquals(32, u.salt.size)
        assertEquals(32, u.token.size)
        assertEquals("wss://broker.example.org/peerjs", u.brokerWss)
        assertEquals("demo", u.brokerKey)
        assertEquals(2_000_000_000L, u.expiresAt)
        assertEquals("test-host", u.serverName)
    }

    @Test fun `brokerkey defaults to peerjs when absent`() {
        val u = EnrollUri.parse(sampleUri.replace("&brokerkey=demo", ""))
        assertEquals("peerjs", u.brokerKey)
    }

    @Test fun `expires and server are optional`() {
        var stripped = sampleUri.replace("&expires=2000000000", "")
        stripped = stripped.replace("&server=test-host", "")
        val u = EnrollUri.parse(stripped)
        assertNull(u.expiresAt)
        assertNull(u.serverName)
    }

    @Test fun `expires that doesn't parse as Long becomes null`() {
        val u = EnrollUri.parse(
            sampleUri.replace("expires=2000000000", "expires=tomorrow"))
        assertNull(u.expiresAt)
    }

    @Test fun `rejects wrong scheme`() {
        assertThrows<IllegalArgumentException> {
            EnrollUri.parse("https://v1?pk=A&salt=B&broker=c&token=D")
        }
    }

    @Test fun `rejects unsupported version`() {
        assertThrows<IllegalArgumentException> {
            EnrollUri.parse(sampleUri.replace("//v1?", "//v2?"))
        }
    }

    @Test fun `rejects missing pk`() {
        assertThrows<IllegalArgumentException> {
            EnrollUri.parse(sampleUri.replace(Regex("pk=[^&]*&"), ""))
        }
    }

    @Test fun `rejects missing salt`() {
        assertThrows<IllegalArgumentException> {
            EnrollUri.parse(sampleUri.replace(Regex("salt=[^&]*&"), ""))
        }
    }

    @Test fun `rejects missing broker`() {
        assertThrows<IllegalArgumentException> {
            EnrollUri.parse(sampleUri.replace(Regex("broker=[^&]*&"), ""))
        }
    }

    @Test fun `rejects missing token`() {
        assertThrows<IllegalArgumentException> {
            EnrollUri.parse(sampleUri.replace(Regex("token=[^&]*&"), ""))
        }
    }

    @Test fun `accepts padded base64url too (lenient)`() {
        // Daemon CLI emits unpadded; copy-pasted from other tooling can have padding.
        val padded = sampleUri.replace("token=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
                                        "token=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8%3D")
        val u = EnrollUri.parse(padded)
        assertEquals(32, u.token.size)
    }

    @Test fun `query keys URL-decode (admin-controlled server name with space)`() {
        val u = EnrollUri.parse(sampleUri.replace("server=test-host", "server=Markus%27%20Server"))
        assertEquals("Markus' Server", u.serverName)
    }

    @Test fun `first-occurrence-wins for duplicate query keys`() {
        // Defensive — matches android.net.Uri.getQueryParameter semantics.
        val u = EnrollUri.parse(sampleUri + "&server=second-value")
        assertEquals("test-host", u.serverName)
    }

    // ─── Trust-model contract ───────────────────────────────────────────
    // These tests don't probe parser correctness — they lock in the
    // documented "hint vs security-boundary" contract from the EnrollUri
    // KDoc. If a future code path starts trusting these for security,
    // this is where the regression should fire first.

    @Test fun `expiresAt is parsed but never enforced by EnrollUri itself`() {
        // The EnrollUri data class has no methods that act on expiresAt;
        // it's a passive data field. Enforcement (if any) lives in
        // EnrollClient as a local fast-fail, and at the daemon as the
        // authoritative check. A forged future expires must therefore
        // round-trip through EnrollUri unchanged.
        val u = EnrollUri.parse(sampleUri.replace("expires=2000000000",
                                                  "expires=99999999999"))
        assertEquals(99_999_999_999L, u.expiresAt)
        // ...and EnrollUri exposes no method whose name suggests
        // enforcement (catches the case where someone adds isExpired() etc.):
        val methods = u::class.java.declaredMethods.map { it.name }
        assertFalse(methods.any { it.startsWith("isExpir") || it == "validate" })
    }

    @Test fun `serverName is opaque text - no implicit trust`() {
        // serverName might be displayed verbatim by UI; ensure newlines
        // and shell metachars round-trip without sanitisation here
        // (sanitisation, if needed, belongs at the UI layer or daemon).
        val ugly = "evil%0Aname%3B%20rm%20-rf%20%2F" // "evil\nname; rm -rf /"
        val u = EnrollUri.parse(sampleUri.replace("server=test-host", "server=$ugly"))
        assertEquals("evil\nname; rm -rf /", u.serverName)
    }

    // ── builder ────────────────────────────────────────────────────

    @Test fun `build then parse round-trips a fully-populated URI`() {
        val u = EnrollUri.parse(sampleUri)
        val rebuilt = EnrollUri.build(
            serverPub = u.serverPub,
            salt = u.salt,
            brokerWss = u.brokerWss,
            brokerKey = u.brokerKey,
            token = u.token,
            expiresAt = u.expiresAt,
            serverName = u.serverName,
        )
        val reparsed = EnrollUri.parse(rebuilt)
        assertArrayEquals(u.serverPub, reparsed.serverPub)
        assertArrayEquals(u.salt, reparsed.salt)
        assertEquals(u.brokerWss, reparsed.brokerWss)
        assertEquals(u.brokerKey, reparsed.brokerKey)
        assertArrayEquals(u.token, reparsed.token)
        assertEquals(u.expiresAt, reparsed.expiresAt)
        assertEquals(u.serverName, reparsed.serverName)
    }

    @Test fun `build emits the wgrtc-enroll v1 scheme`() {
        val out = EnrollUri.build(
            serverPub = ByteArray(32) { 1 },
            salt = ByteArray(32) { 2 },
            brokerWss = "wss://example/peerjs",
            brokerKey = "k",
            token = ByteArray(32) { 3 },
        )
        assertTrue(out.startsWith("wgrtc-enroll://v1?"),
            "expected wgrtc-enroll://v1 prefix; got: $out")
    }

    @Test fun `build emits URL-safe-no-padding base64 for 32-byte fields`() {
        val out = EnrollUri.build(
            serverPub = ByteArray(32) { 1 },
            salt = ByteArray(32) { 2 },
            brokerWss = "wss://x/y",
            brokerKey = "k",
            token = ByteArray(32) { 3 },
        )
        // Each 32-byte value is exactly 43 base64-url chars (no padding).
        // The pk= field appears as `pk=<43 chars>&` or `&pk=...`.
        assertTrue(out.matches(Regex(".*\\bpk=[A-Za-z0-9_-]{43}(&|\$).*")),
            "pk should be 43 base64-url chars, no padding; got: $out")
        assertTrue(out.matches(Regex(".*\\bsalt=[A-Za-z0-9_-]{43}(&|\$).*")))
        assertTrue(out.matches(Regex(".*\\btoken=[A-Za-z0-9_-]{43}(&|\$).*")))
        // The base64 fields themselves carry no '=' padding (URL-safe).
        // The URI does have '=' as the key=value separator — that's fine.
    }

    @Test fun `build URL-encodes special characters in brokerWss`() {
        val out = EnrollUri.build(
            serverPub = ByteArray(32),
            salt = ByteArray(32),
            brokerWss = "wss://broker.example.com:443/ws/peerjs",
            brokerKey = "k",
            token = ByteArray(32),
        )
        // Slashes/colons in the broker value should be percent-encoded so
        // the URI parser splits cleanly. Round-trip is the real check.
        val parsed = EnrollUri.parse(out)
        assertEquals("wss://broker.example.com:443/ws/peerjs", parsed.brokerWss)
    }

    @Test fun `build URL-encodes special chars in serverName`() {
        val out = EnrollUri.build(
            serverPub = ByteArray(32),
            salt = ByteArray(32),
            brokerWss = "wss://x/y",
            brokerKey = "k",
            token = ByteArray(32),
            serverName = "Markus' phone (5G)",
        )
        val parsed = EnrollUri.parse(out)
        assertEquals("Markus' phone (5G)", parsed.serverName)
    }

    @Test fun `build omits expires and server when null`() {
        val out = EnrollUri.build(
            serverPub = ByteArray(32),
            salt = ByteArray(32),
            brokerWss = "wss://x/y",
            brokerKey = "k",
            token = ByteArray(32),
            expiresAt = null,
            serverName = null,
        )
        assertFalse(out.contains("expires="),
            "expires= should be omitted when null; got: $out")
        assertFalse(out.contains("server="),
            "server= should be omitted when null; got: $out")
        // Required fields still present.
        assertTrue(out.contains("pk="))
        assertTrue(out.contains("salt="))
        assertTrue(out.contains("broker="))
        assertTrue(out.contains("token="))
    }

    @Test fun `build emits brokerkey when not the default peerjs`() {
        val withCustom = EnrollUri.build(
            serverPub = ByteArray(32), salt = ByteArray(32),
            brokerWss = "wss://x/y", brokerKey = "custom",
            token = ByteArray(32),
        )
        assertTrue(withCustom.contains("brokerkey=custom"))
        // When brokerKey is the default, it can be omitted to keep
        // URI short — but emitting it is also legal. We emit always
        // for predictability; both behaviors round-trip via parse().
        val withDefault = EnrollUri.build(
            serverPub = ByteArray(32), salt = ByteArray(32),
            brokerWss = "wss://x/y", brokerKey = "peerjs",
            token = ByteArray(32),
        )
        assertEquals("peerjs", EnrollUri.parse(withDefault).brokerKey)
    }

    @Test fun `build rejects wrong-length keys`() {
        assertThrows<IllegalArgumentException> {
            EnrollUri.build(
                serverPub = ByteArray(31), // wrong size
                salt = ByteArray(32),
                brokerWss = "wss://x/y", brokerKey = "k",
                token = ByteArray(32),
            )
        }
        assertThrows<IllegalArgumentException> {
            EnrollUri.build(
                serverPub = ByteArray(32),
                salt = ByteArray(33), // wrong size
                brokerWss = "wss://x/y", brokerKey = "k",
                token = ByteArray(32),
            )
        }
        assertThrows<IllegalArgumentException> {
            EnrollUri.build(
                serverPub = ByteArray(32),
                salt = ByteArray(32),
                brokerWss = "wss://x/y", brokerKey = "k",
                token = ByteArray(8), // wrong size
            )
        }
    }
}
