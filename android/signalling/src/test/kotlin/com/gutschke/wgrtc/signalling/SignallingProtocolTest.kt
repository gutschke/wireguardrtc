package com.gutschke.wgrtc.signalling

import com.goterl.lazysodium.LazySodiumJava
import com.goterl.lazysodium.SodiumJava
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonObject
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import java.util.Base64

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class SignallingProtocolTest {

    @BeforeAll fun installJvmSodium() {
        Sodium.setForTest(LazySodiumJava(SodiumJava()))
    }
    @AfterAll fun restoreSodium() { Sodium.setForTest(null) }

    /** Build an OFFER envelope shaped exactly like what the daemon emits. */
    private fun envelope(
        kind: String? = null,
        blob: String = "Z",
        v: Int = PROTOCOL_VERSION,
    ) = buildJsonObject {
        put("type", "OFFER")
        put("src", "daemon-id")
        putJsonObject("payload") {
            put("type", "data"); put("connectionId", "dc_x")
            put("label", "dc_x"); put("reliable", false)
            put("serialization", "binary")
            putJsonObject("sdp") { put("sdp", "stub"); put("type", "offer") }
            putJsonObject("metadata") {
                put("v", v)
                if (kind != null) put("kind", kind)
                put("blob", blob)
            }
        }
    }

    @Test fun `extractSignallingOffer pulls blob from a kind-less OFFER`() {
        val r = extractSignallingOffer(envelope(kind = null, blob = "abc"))
        assertEquals("abc", r)
    }

    @Test fun `extractSignallingOffer rejects enrolment OFFERs`() {
        // The daemon discriminates kinds; we mirror that.
        assertNull(extractSignallingOffer(envelope(kind = "enroll")))
        assertNull(extractSignallingOffer(envelope(kind = "enroll_ok")))
        assertNull(extractSignallingOffer(envelope(kind = "enroll_err")))
    }

    @Test fun `extractSignallingOffer rejects non-OFFER messages`() {
        assertNull(extractSignallingOffer(Json.parseToJsonElement("""{"type":"OPEN"}""")))
        assertNull(extractSignallingOffer(
            Json.parseToJsonElement("""{"type":"HEARTBEAT"}""")))
    }

    @Test fun `extractSignallingOffer rejects mismatched protocol version`() {
        assertNull(extractSignallingOffer(envelope(v = 99)))
    }

    @Test fun `extractSignallingOffer accepts empty kind as signalling`() {
        // Defensive — some daemons may emit `"kind": ""`; treat as unset.
        val msg = buildJsonObject {
            put("type", "OFFER")
            putJsonObject("payload") {
                putJsonObject("metadata") {
                    put("v", PROTOCOL_VERSION)
                    put("kind", "")
                    put("blob", "x")
                }
            }
        }
        assertEquals("x", extractSignallingOffer(msg))
    }

    // ─── decryptEndpointBlob ───────────────────────────────────────────

    private val key = ByteArray(32) { 0x55.toByte() }

    /** Build a properly-encrypted endpoint blob the way the daemon would —
     * current wire format wraps the (ip, port) in a one-element
     * candidates array. */
    private fun encryptEndpoint(
        ip: String, port: Int, ts: Long,
        v: Int = PROTOCOL_VERSION,
        boxKey: ByteArray = key,
    ): String {
        val plain = """{"v":$v,"ts":$ts,
            "candidates":[{"ip":"$ip","port":$port,"kind":"stun"}]}""".trimIndent()
        val ct = secretboxEncrypt(plain.toByteArray(Charsets.UTF_8), boxKey)
        return Base64.getEncoder().encodeToString(ct)
    }

    @Test fun `decryptEndpointBlob happy path`() {
        val now = 1_700_000_000L
        val blob = encryptEndpoint("192.0.2.5", 51820, ts = now)
        val r = decryptEndpointBlob(key, blob, nowEpochSeconds = now)
        assertEquals(EndpointUpdate("192.0.2.5", 51820, now), r)
    }

    @Test fun `decryptEndpointBlob within freshness window passes`() {
        val now = 1_700_000_000L
        val blob = encryptEndpoint("192.0.2.5", 51820, ts = now - 80)
        assertNotNull(decryptEndpointBlob(key, blob, nowEpochSeconds = now))
    }

    @Test fun `decryptEndpointBlob rejects stale timestamp`() {
        val now = 1_700_000_000L
        val blob = encryptEndpoint("192.0.2.5", 51820, ts = now - 200)
        assertNull(decryptEndpointBlob(key, blob, nowEpochSeconds = now))
    }

    @Test fun `decryptEndpointBlob rejects future timestamp beyond window`() {
        val now = 1_700_000_000L
        val blob = encryptEndpoint("192.0.2.5", 51820, ts = now + 200)
        assertNull(decryptEndpointBlob(key, blob, nowEpochSeconds = now))
    }

    @Test fun `decryptEndpointBlob rejects wrong key (silent)`() {
        val now = 1_700_000_000L
        val blob = encryptEndpoint("192.0.2.5", 51820, ts = now,
                                   boxKey = ByteArray(32) { 0x77.toByte() })
        assertNull(decryptEndpointBlob(key, blob, nowEpochSeconds = now))
    }

    @Test fun `decryptEndpointBlob rejects malformed base64`() {
        assertNull(decryptEndpointBlob(key, "not-valid-base64!!!"))
    }

    @Test fun `decryptEndpointBlob rejects oversized ciphertext (DoS guard)`() {
        // Construct an oversized base64 string — the cap rejects it
        // before we do any crypto, so an attacker can't make us spend
        // CPU on a giant decrypt that would fail anyway.
        val tooBig = "A".repeat(MAX_SIGBOX_CIPHERTEXT_B64 + 1)
        assertNull(decryptEndpointBlob(key, tooBig))
    }

    @Test fun `decryptEndpointBlob rejects v mismatch`() {
        val now = 1_700_000_000L
        val blob = encryptEndpoint("192.0.2.5", 51820, ts = now, v = 99)
        assertNull(decryptEndpointBlob(key, blob, nowEpochSeconds = now))
    }

    @Test fun `decryptEndpointBlob rejects bad port`() {
        val now = 1_700_000_000L
        val plain = """{"v":1,"ts":$now,
            "candidates":[{"ip":"192.0.2.5","port":0}]}""".trimIndent()
        val ct = secretboxEncrypt(plain.toByteArray(), key)
        val blob = Base64.getEncoder().encodeToString(ct)
        assertNull(decryptEndpointBlob(key, blob, nowEpochSeconds = now))
    }

    @Test fun `decryptEndpointBlob rejects empty ip`() {
        val now = 1_700_000_000L
        val plain = """{"v":1,"ts":$now,
            "candidates":[{"ip":"","port":51820}]}""".trimIndent()
        val ct = secretboxEncrypt(plain.toByteArray(), key)
        val blob = Base64.getEncoder().encodeToString(ct)
        assertNull(decryptEndpointBlob(key, blob, nowEpochSeconds = now))
    }

    // ─── candidates-array form (current wire format) ───────────────────

    private fun encryptCandidates(
        ts: Long,
        candidates: String, // raw JSON-array body, e.g. '[{"ip":...}]'
        v: Int = PROTOCOL_VERSION,
        boxKey: ByteArray = key,
    ): String {
        val plain = """{"v":$v,"ts":$ts,"candidates":$candidates}"""
        val ct = secretboxEncrypt(plain.toByteArray(Charsets.UTF_8), boxKey)
        return Base64.getEncoder().encodeToString(ct)
    }

    @Test fun `candidates with single STUN entry returns first candidate`() {
        val now = 1_700_000_000L
        val blob = encryptCandidates(now,
            """[{"ip":"1.2.3.4","port":51820,"kind":"stun"}]""")
        val r = decryptEndpointBlob(key, blob, nowEpochSeconds = now)
        assertNotNull(r)
        assertEquals("1.2.3.4", r!!.ip)
        assertEquals(51820, r.port)
    }

    @Test fun `candidates with LAN-then-STUN returns the LAN candidate`() {
        val now = 1_700_000_000L
        val blob = encryptCandidates(now,
            """[{"ip":"192.168.43.1","port":51820,"kind":"lan"},
                {"ip":"1.2.3.4","port":51820,"kind":"stun"}]""".trimIndent())
        val r = decryptEndpointBlob(key, blob, nowEpochSeconds = now)
        assertNotNull(r)
        assertEquals("192.168.43.1", r!!.ip)
    }

    @Test fun `empty candidates list returns null (signal_wake response shape)`() {
        // signal_wake's plaintext carries an empty list — sender claims
        // no endpoint. decryptEndpointBlob is for receivers consuming
        // an endpoint claim, so empty → null is correct.
        val now = 1_700_000_000L
        val blob = encryptCandidates(now, "[]")
        assertNull(decryptEndpointBlob(key, blob, nowEpochSeconds = now))
    }

    @Test fun `candidates skip malformed entries silently and return next valid`() {
        val now = 1_700_000_000L
        val blob = encryptCandidates(now,
            """[{"ip":"not-an-ip","port":51820},
                {"ip":"1.2.3.4","port":"oops"},
                {"ip":"1.2.3.4","port":51820,"kind":"stun"}]""".trimIndent())
        val r = decryptEndpointBlob(key, blob, nowEpochSeconds = now)
        assertNotNull(r)
        assertEquals("1.2.3.4", r!!.ip)
    }

    @Test fun `legacy ip+port-only payload rejected (post-cutover wire format)`() {
        // Per the user's directive 2026-05-07, we DO NOT honour the v0
        // single-endpoint form — every plaintext now carries
        // candidates. This test pins the cutover.
        val now = 1_700_000_000L
        val plain = """{"v":1,"ts":$now,"ip":"1.2.3.4","port":51820}"""
        val ct = secretboxEncrypt(plain.toByteArray(Charsets.UTF_8), key)
        val blob = Base64.getEncoder().encodeToString(ct)
        assertNull(decryptEndpointBlob(key, blob, nowEpochSeconds = now))
    }

    // ─── bootstrap-deadlock guard (Step A) ────────────────────────────
    // `rejectIfInside` carries the tunnel's `[Peer] AllowedIPs`. Any
    // candidate IP inside that set would deadlock kernel-WG bringup —
    // the kernel would route handshake packets back into the very
    // tunnel needing the handshake to come up. See
    //§"Receiver
    // rules / Bootstrap deadlock".

    @Test fun `deadlock guard rejects single in-range candidate`() {
        val now = 1_700_000_000L
        val blob = encryptCandidates(now,
            """[{"ip":"10.0.0.5","port":51820,"kind":"lan"}]""")
        // Tunnel routes 10.0.0.0/24 — the candidate IP is inside.
        assertNull(decryptEndpointBlob(key, blob, nowEpochSeconds = now,
            rejectIfInside = listOf("10.0.0.0/24")))
    }

    @Test fun `deadlock guard with 0_0_0_0 0 rejects all v4 candidates`() {
        // The classic full-tunnel VPN scenario: AllowedIPs = 0.0.0.0/0.
        // Every v4 endpoint is a deadlock — there's no working
        // endpoint without an explicit route exception, which
        // wg-quick's `Table = off` mode is supposed to handle but
        // we can't rely on that being set.
        val now = 1_700_000_000L
        val blob = encryptCandidates(now, """
            [{"ip":"203.0.113.5","port":51820,"kind":"stun"},
             {"ip":"192.168.43.1","port":51820,"kind":"lan"}]
        """.trimIndent())
        assertNull(decryptEndpointBlob(key, blob, nowEpochSeconds = now,
            rejectIfInside = listOf("0.0.0.0/0")))
    }

    @Test fun `deadlock guard skips in-range and keeps later out-of-range`() {
        val now = 1_700_000_000L
        val blob = encryptCandidates(now, """
            [{"ip":"10.0.0.5","port":51820,"kind":"lan"},
             {"ip":"203.0.113.5","port":51820,"kind":"stun"}]
        """.trimIndent())
        val r = decryptEndpointBlob(key, blob, nowEpochSeconds = now,
            rejectIfInside = listOf("10.0.0.0/24"))
        assertEquals("203.0.113.5", r?.ip)
    }

    @Test fun `deadlock guard with multiple ranges`() {
        val now = 1_700_000_000L
        val blob = encryptCandidates(now, """
            [{"ip":"10.0.0.5","port":51820,"kind":"lan"},
             {"ip":"192.168.42.1","port":51820,"kind":"lan"},
             {"ip":"203.0.113.5","port":51820,"kind":"stun"}]
        """.trimIndent())
        val r = decryptEndpointBlob(key, blob, nowEpochSeconds = now,
            rejectIfInside = listOf("10.0.0.0/24", "192.168.0.0/16"))
        assertEquals("203.0.113.5", r?.ip)
    }

    @Test fun `deadlock guard with empty allowedIps preserves default behaviour`() {
        // When the caller has nothing to reject against, behaviour is
        // identical to the no-arg form — no candidate is dropped on
        // these grounds.
        val now = 1_700_000_000L
        val blob = encryptCandidates(now,
            """[{"ip":"10.0.0.5","port":51820,"kind":"lan"}]""")
        val r = decryptEndpointBlob(key, blob, nowEpochSeconds = now,
            rejectIfInside = emptyList())
        assertEquals("10.0.0.5", r?.ip)
    }

    @Test fun `deadlock guard returns full list ordering`() {
        // decryptEndpointCandidates (the multi-candidate API) preserves
        // sender-supplied order after deadlock filtering.
        val now = 1_700_000_000L
        val blob = encryptCandidates(now, """
            [{"ip":"10.0.0.5","port":51820,"kind":"lan"},
             {"ip":"192.168.42.1","port":51820,"kind":"lan"},
             {"ip":"203.0.113.5","port":51820,"kind":"stun"},
             {"ip":"198.51.100.1","port":51820,"kind":"stun"}]
        """.trimIndent())
        val list = decryptEndpointCandidates(key, blob, nowEpochSeconds = now,
            rejectIfInside = listOf("10.0.0.0/24"))
        assertNotNull(list)
        assertEquals(
            listOf("192.168.42.1", "203.0.113.5", "198.51.100.1"),
            list!!.map { it.ip }
        )
    }

    @Test fun `deadlock guard returns null when ALL candidates rejected`() {
        val now = 1_700_000_000L
        val blob = encryptCandidates(now, """
            [{"ip":"10.0.0.5","port":51820,"kind":"lan"},
             {"ip":"10.0.0.7","port":51820,"kind":"lan"}]
        """.trimIndent())
        // Strict-mode-style outcome: list collapses to empty → null,
        // caller knows no candidate survived and surfaces the error.
        assertNull(decryptEndpointCandidates(key, blob, nowEpochSeconds = now,
            rejectIfInside = listOf("10.0.0.0/24")))
    }
}
