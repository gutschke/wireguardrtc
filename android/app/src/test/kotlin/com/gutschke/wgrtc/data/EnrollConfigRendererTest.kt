package com.gutschke.wgrtc.data

import com.gutschke.wgrtc.signalling.EnrollOkPlain
import com.gutschke.wgrtc.signalling.EnrollResult
import com.gutschke.wgrtc.signalling.EnrollUri
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

class EnrollConfigRendererTest {

    private val sampleUri = EnrollUri.parse(
        "wgrtc-enroll://v1?" +
        "pk=AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA&" +
        "salt=ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8&" +
        "broker=wss%3A%2F%2Fbroker.example.org%2Fpeerjs&" +
        "brokerkey=demo&" +
        "token=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
    )

    private fun ok(plain: EnrollOkPlain) = EnrollResult.Ok(
        plaintext = plain,
        clientPubKey = ByteArray(32) { 0xAA.toByte() },
        clientPrivKey = ByteArray(32) { 0xBB.toByte() },
    )

    private val basePlain = EnrollOkPlain(
        version = 1,
        timestamp = 1_700_000_000L,
        address = "10.0.0.5/32",
        serverPubkey = "SERVER_PUB_KEY_BASE64==",
        serverEndpointHint = "1.2.3.4:51820",
        name = "alice",
    )

    @Test fun `happy path renders a syntactically-valid wg-quick block`() {
        val cfg = renderEnrollConfig(sampleUri, ok(basePlain))
        // Required wg-quick sections are present.
        assertTrue(cfg.contains("[Interface]"))
        assertTrue(cfg.contains("[Peer]"))
        // Required keys.
        assertTrue(cfg.contains("PrivateKey = "), "no PrivateKey line\n$cfg")
        assertTrue(cfg.contains("Address = 10.0.0.5/32"))
        assertTrue(cfg.contains("PublicKey = SERVER_PUB_KEY_BASE64=="))
        assertTrue(cfg.contains("Endpoint = 1.2.3.4:51820"))
        // Defaults applied when daemon omits them.
        // Canonical (no whitespace) — see WgAllowedIps for the
        // ChromeOS-rejects-whitespace compat constraint.
        assertTrue(cfg.contains("AllowedIPs = 0.0.0.0/0,::/0"))
        assertTrue(cfg.contains("PersistentKeepalive = 25"))
        // Fields the daemon didn't set must NOT leak null literals.
        assertFalse(cfg.contains("null"), "null literal in output:\n$cfg")
        assertFalse(cfg.contains("DNS = "))
        assertFalse(cfg.contains("MTU = "))
    }

    @Test fun `falls back to URI server pubkey when ENROLL_OK omits it`() {
        val cfg = renderEnrollConfig(sampleUri, ok(basePlain.copy(serverPubkey = null)))
        // The fallback uses Base64 of uri.serverPub (32 bytes → 44 chars padded).
        val pubLine = cfg.lineSequence().first { it.startsWith("PublicKey = ") }
        val pubB64 = pubLine.removePrefix("PublicKey = ")
        assertEquals(44, pubB64.length, "expected 44-char padded base64; got '$pubB64'")
        assertTrue(pubB64.endsWith("="), "expected padding; got '$pubB64'")
    }

    @Test fun `missing server_endpoint_hint throws with actionable message`() {
        val ex = assertThrows<IllegalStateException> {
            renderEnrollConfig(sampleUri, ok(basePlain.copy(serverEndpointHint = null)))
        }
        // The message is what the user sees in the app's error banner —
        // it must name the daemon-side fix (PublicIp/STUN), not just
        // shrug.
        assertTrue(ex.message?.contains("PublicIp") == true ||
                   ex.message?.contains("STUN") == true,
            "message should mention the daemon-side fix; got: ${ex.message}")
    }

    @Test fun `daemon-supplied dns and mtu pass through`() {
        val cfg = renderEnrollConfig(sampleUri, ok(basePlain.copy(
            dns = "1.1.1.1, 8.8.8.8", mtu = 1380)))
        assertTrue(cfg.contains("DNS = 1.1.1.1, 8.8.8.8"))
        assertTrue(cfg.contains("MTU = 1380"))
    }

    @Test fun `daemon-supplied allowed_ips and keepalive override defaults`() {
        val cfg = renderEnrollConfig(sampleUri, ok(basePlain.copy(
            allowedIps = "10.0.0.0/8", keepalive = 60)))
        assertTrue(cfg.contains("AllowedIPs = 10.0.0.0/8"))
        // Make sure the dual-stack default (in either historic
        // spaced form or canonical form) didn't leak through.
        assertFalse(cfg.contains("AllowedIPs = 0.0.0.0/0, ::/0"))
        assertFalse(cfg.contains("AllowedIPs = 0.0.0.0/0,::/0"))
        assertTrue(cfg.contains("PersistentKeepalive = 60"))
    }

    @Test fun `output ends with single trailing newline (wg-quick parser tolerant)`() {
        val cfg = renderEnrollConfig(sampleUri, ok(basePlain))
        assertTrue(cfg.endsWith("\n"))
        // Not double-newline-terminated (some parsers care).
        assertFalse(cfg.endsWith("\n\n\n"))
    }

    @Test fun `Interface block precedes Peer block`() {
        val cfg = renderEnrollConfig(sampleUri, ok(basePlain))
        val ifIdx = cfg.indexOf("[Interface]")
        val peerIdx = cfg.indexOf("[Peer]")
        assertTrue(ifIdx >= 0 && peerIdx > ifIdx,
            "expected Interface before Peer; got Interface@$ifIdx Peer@$peerIdx")
    }
}
