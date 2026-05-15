package com.gutschke.wgrtc.data

import com.goterl.lazysodium.LazySodiumJava
import com.goterl.lazysodium.SodiumJava
import com.gutschke.wgrtc.signalling.EnrollOkPlain
import com.gutschke.wgrtc.signalling.EnrollRequestPlain
import com.gutschke.wgrtc.signalling.EndpointCandidate
import com.gutschke.wgrtc.signalling.PROTOCOL_VERSION
import com.gutschke.wgrtc.signalling.Sodium
import com.gutschke.wgrtc.signalling.buildEnrollEnvelope
import com.gutschke.wgrtc.signalling.deriveEnrollKey
import com.gutschke.wgrtc.signalling.extractInboundEnroll
import com.gutschke.wgrtc.signalling.pubKeyFromPrivate
import com.gutschke.wgrtc.signalling.routingId
import com.gutschke.wgrtc.signalling.secretboxDecrypt
import com.gutschke.wgrtc.signalling.secretboxEncrypt
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import org.junit.jupiter.api.io.TempDir
import java.io.File
import java.nio.file.Path
import java.security.SecureRandom
import java.util.Base64

/**
 * End-to-end protocol tests for [InboundEnrollHandler]. Each test
 * builds a real client-side ENROLL envelope (real keypairs, real
 * crypto), feeds it through the handler, and verifies both the
 * outgoing envelope shape and the persistent state changes (token
 * consumption, allocated peer).
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class InboundEnrollHandlerTest {

    @BeforeAll fun installJvmSodium() {
        Sodium.setForTest(LazySodiumJava(SodiumJava()))
    }
    @AfterAll fun restoreSodium() { Sodium.setForTest(null) }

    private val rng = SecureRandom()

    /** Generates a fresh server (host) keypair + client keypair, plus the
     * salt used for routing-id calculation. Returns everything a test
     * needs to drive the handler. */
    private data class TestFixture(
        val serverPriv: ByteArray,
        val serverPub: ByteArray,
        val serverPubB64: String,
        val clientPriv: ByteArray,
        val clientPub: ByteArray,
        val clientPubB64: String,
        val saltBytes: ByteArray,
        val srcId: String,
    )

    private fun fixture(): TestFixture {
        val serverPriv = ByteArray(32).also { rng.nextBytes(it) }
        val serverPub = pubKeyFromPrivate(serverPriv)
        val clientPriv = ByteArray(32).also { rng.nextBytes(it) }
        val clientPub = pubKeyFromPrivate(clientPriv)
        val saltBytes = ByteArray(32) { 0xCC.toByte() }
        val clientPubB64 = b64.encodeToString(clientPub)
        return TestFixture(
            serverPriv = serverPriv,
            serverPub = serverPub,
            serverPubB64 = b64.encodeToString(serverPub),
            clientPriv = clientPriv,
            clientPub = clientPub,
            clientPubB64 = clientPubB64,
            saltBytes = saltBytes,
            srcId = routingId(clientPubB64, saltBytes),
        )
    }

    private fun store(dir: Path) = PendingTokensStore(File(dir.toFile(), "pending.json"))

    private fun hostState(
        f: TestFixture,
        subnet: String = "10.99.0.0/24",
        hostIp: String = "10.99.0.1",
        listenPort: Int = 51820,
        endpoint: String? = "192.0.2.1:51820",
        candidates: List<EndpointCandidate> = emptyList(),
        allocatedIps: Set<String> = emptySet(),
        // V6.3 — defaults keep legacy tests v4-only.  Pass non-null
        // subnetV6 + hostIpV6 to exercise dual-stack allocation.
        subnetV6: String? = null,
        hostIpV6: String? = null,
        allocatedIpsV6: Set<String> = emptySet(),
    ) = InboundEnrollHandler.HostState(
        serverPrivBytes = f.serverPriv,
        serverPubB64 = f.serverPubB64,
        listenPort = listenPort,
        hostIp = hostIp,
        subnet = subnet,
        saltBytes = f.saltBytes,
        publicEndpointHint = endpoint,
        candidates = candidates,
        allocatedIps = allocatedIps,
        subnetV6 = subnetV6,
        hostIpV6 = hostIpV6,
        allocatedIpsV6 = allocatedIpsV6,
    )

    /** Encrypt a request plaintext using the same key derivation
     * the daemon uses (server_priv ⊕ client_pub ⊕ token). */
    private fun buildRequestBlob(
        f: TestFixture, tokenSecret: ByteArray, ts: Long, hint: String = "alice",
    ): String {
        val tokenB64 = b64.encodeToString(tokenSecret)
        val plaintext = """{"v":$PROTOCOL_VERSION,"ts":$ts,"token_check":"$tokenB64",
            |"hint":"$hint","device":"test"}""".trimMargin().replace("\n", "")
        // Client side derivation.
        val key = deriveEnrollKey(f.clientPriv, f.serverPub, tokenSecret)
        val ct = secretboxEncrypt(plaintext.toByteArray(), key)
        return b64.encodeToString(ct)
    }

    /** Build the full inbound envelope (as a JSON string the handler
     * will eventually receive over the WSS) so tests parse the same
     * shape the runtime parses. */
    private fun buildInboundEnvelopeJson(
        f: TestFixture, blobB64: String, dstRoutingId: String = "deadbeef".repeat(8),
    ): String {
        val env = buildEnrollEnvelope(
            dstRoutingId = dstRoutingId,
            clientPubBase64 = f.clientPubB64,
            blobBase64 = blobB64,
        ) as JsonObject
        // Inject src as the broker would on forwarding.
        val withSrc = JsonObject(env.toMutableMap().apply {
            put("src", JsonPrimitive(f.srcId))
        })
        return withSrc.toString()
    }

    // ─── tests ────────────────────────────────────────────────────────

    @Test fun `valid enroll yields enroll_ok with allocated ip`(@TempDir dir: Path) {
        val f = fixture()
        val s = store(dir)
        val tok = s.mint("alice-laptop", 600_000L, now = 1000L)
        val ts = 1L
        val blob = buildRequestBlob(f, tok.tokenSecret, ts)
        val envJson = buildInboundEnvelopeJson(f, blob)
        val handler = InboundEnrollHandler(
            tokens = s,
            nowMs = { 1000L },
            nowSec = { ts },
        )
        val parsed = extractInboundEnroll(Json.parseToJsonElement(envJson))!!
        val result = handler.handle(parsed, hostState(f))

        assertTrue(result is InboundEnrollHandler.Result.Reply,
            "expected Reply, got $result")
        result as InboundEnrollHandler.Result.Reply
        assertNotNull(result.newPeer)
        assertEquals(f.clientPubB64, result.newPeer!!.pubkeyB64)
        assertEquals("alice-laptop", result.newPeer.nameHint)
        // First free /32 in 10.99.0.0/24 with host=.1 → .2.
        assertEquals("10.99.0.2", result.newPeer.assignedIp)

        // Token must now be consumed (single-use).
        assertNull(s.lookup(tok.tokenSecret, now = 2000L))

        // Decrypt the response blob and verify shape.
        val key = deriveEnrollKey(f.clientPriv, f.serverPub, tok.tokenSecret)
        val responseEnv = Json.parseToJsonElement(result.envelopeJson) as JsonObject
        val md = ((responseEnv["payload"] as JsonObject)["metadata"]) as JsonObject
        assertEquals("enroll_ok", (md["kind"] as JsonPrimitive).content)
        assertEquals(f.serverPubB64, (md["server_pub"] as JsonPrimitive).content)
        val blobOut = (md["blob"] as JsonPrimitive).content
        val ct = Base64.getDecoder().decode(blobOut)
        val plain = secretboxDecrypt(ct, key)
        assertNotNull(plain, "could not decrypt enroll_ok blob")
        val ok = Json.decodeFromString(EnrollOkPlain.serializer(),
                                       plain!!.toString(Charsets.UTF_8))
        assertEquals("10.99.0.2/32", ok.address)
        assertEquals(f.serverPubB64, ok.serverPubkey)
        assertEquals("192.0.2.1:51820", ok.serverEndpointHint)
        assertEquals("alice-laptop", ok.name)
        assertEquals(25, ok.keepalive)
    }

    @Test fun `enroll skips already-used ips`(@TempDir dir: Path) {
        val f = fixture()
        val s = store(dir)
        val tok = s.mint("bob", 600_000L, now = 1000L)
        val blob = buildRequestBlob(f, tok.tokenSecret, ts = 1L)
        val envJson = buildInboundEnvelopeJson(f, blob)
        val handler = InboundEnrollHandler(s, nowMs = { 1000L }, nowSec = { 1L })
        val parsed = extractInboundEnroll(Json.parseToJsonElement(envJson))!!
        val result = handler.handle(parsed, hostState(f,
            allocatedIps = setOf("10.99.0.2", "10.99.0.3")))
        result as InboundEnrollHandler.Result.Reply
        assertEquals("10.99.0.4", result.newPeer!!.assignedIp)
    }

    @Test fun `mismatched src silently ignored`(@TempDir dir: Path) {
        val f = fixture()
        val s = store(dir)
        val tok = s.mint("eve", 600_000L, now = 1000L)
        val blob = buildRequestBlob(f, tok.tokenSecret, ts = 1L)
        val env = buildEnrollEnvelope(
            dstRoutingId = "deadbeef".repeat(8),
            clientPubBase64 = f.clientPubB64,
            blobBase64 = blob,
        ) as JsonObject
        // Inject a WRONG src.
        val withWrongSrc = JsonObject(env.toMutableMap().apply {
            put("src", JsonPrimitive("00000000".repeat(8)))
        })
        val handler = InboundEnrollHandler(s, nowMs = { 1000L }, nowSec = { 1L })
        val result = handler.handle(extractInboundEnroll(withWrongSrc)!!, hostState(f))
        assertTrue(result is InboundEnrollHandler.Result.Ignore)
        // Token NOT consumed.
        assertNotNull(s.lookup(tok.tokenSecret, now = 1000L))
    }

    @Test fun `no matching token silently ignored`(@TempDir dir: Path) {
        val f = fixture()
        val s = store(dir)
        // Mint a real token, but encrypt with a DIFFERENT random token.
        s.mint("real", 600_000L, now = 1000L)
        val fakeToken = ByteArray(32).also { rng.nextBytes(it) }
        val blob = buildRequestBlob(f, fakeToken, ts = 1L)
        val envJson = buildInboundEnvelopeJson(f, blob)
        val handler = InboundEnrollHandler(s, nowMs = { 1000L }, nowSec = { 1L })
        val parsed = extractInboundEnroll(Json.parseToJsonElement(envJson))!!
        val result = handler.handle(parsed, hostState(f))
        assertTrue(result is InboundEnrollHandler.Result.Ignore,
            "expected silent ignore on no-matching-token, got $result")
    }

    @Test fun `consumed token returns enroll_err TOKEN_USED`(@TempDir dir: Path) {
        val f = fixture()
        val s = store(dir)
        val tok = s.mint("frank", 600_000L, now = 1000L)
        // Pre-consume so the handler sees a used token.
        s.consume(tok.tokenSecret, now = 2000L)
        val blob = buildRequestBlob(f, tok.tokenSecret, ts = 3L)
        val envJson = buildInboundEnvelopeJson(f, blob)
        val handler = InboundEnrollHandler(s, nowMs = { 3000L }, nowSec = { 3L })
        val parsed = extractInboundEnroll(Json.parseToJsonElement(envJson))!!
        val result = handler.handle(parsed, hostState(f))
        assertTrue(result is InboundEnrollHandler.Result.Reply)
        result as InboundEnrollHandler.Result.Reply
        assertNull(result.newPeer, "TOKEN_USED must not allocate a peer")
        // Verify it's an enroll_err with TOKEN_USED.
        val md = (((Json.parseToJsonElement(result.envelopeJson) as JsonObject)
                   ["payload"] as JsonObject)["metadata"]) as JsonObject
        assertEquals("enroll_err", (md["kind"] as JsonPrimitive).content)
        // Decrypt to verify the code.
        val key = deriveEnrollKey(f.clientPriv, f.serverPub, tok.tokenSecret)
        val ct = Base64.getDecoder().decode((md["blob"] as JsonPrimitive).content)
        val plain = secretboxDecrypt(ct, key)
        val errJson = Json.parseToJsonElement(plain!!.toString(Charsets.UTF_8)) as JsonObject
        assertEquals("TOKEN_USED", (errJson["code"] as JsonPrimitive).content)
    }

    @Test fun `stale ts silently ignored`(@TempDir dir: Path) {
        val f = fixture()
        val s = store(dir)
        val tok = s.mint("stale", 600_000L, now = 1000L)
        // ts is 200 seconds in the past — outside the 90s freshness window.
        val blob = buildRequestBlob(f, tok.tokenSecret, ts = 100L)
        val envJson = buildInboundEnvelopeJson(f, blob)
        val handler = InboundEnrollHandler(s, nowMs = { 300_000L }, nowSec = { 300L })
        val parsed = extractInboundEnroll(Json.parseToJsonElement(envJson))!!
        val result = handler.handle(parsed, hostState(f))
        assertTrue(result is InboundEnrollHandler.Result.Ignore)
        // Token still active.
        assertNotNull(s.lookup(tok.tokenSecret, now = 300_000L))
    }

    @Test fun `subnet exhaustion returns enroll_err PROVISION_FAILED`(@TempDir dir: Path) {
        val f = fixture()
        val s = store(dir)
        val tok = s.mint("over", 600_000L, now = 1000L)
        val blob = buildRequestBlob(f, tok.tokenSecret, ts = 1L)
        val envJson = buildInboundEnvelopeJson(f, blob)
        // /29 has hosts .1..6; reserve all of them.
        val hostState = hostState(f,
            subnet = "10.99.0.0/29",
            allocatedIps = setOf("10.99.0.2", "10.99.0.3",
                                 "10.99.0.4", "10.99.0.5", "10.99.0.6"))
        val handler = InboundEnrollHandler(s, nowMs = { 1000L }, nowSec = { 1L })
        val parsed = extractInboundEnroll(Json.parseToJsonElement(envJson))!!
        val result = handler.handle(parsed, hostState)
        assertTrue(result is InboundEnrollHandler.Result.Reply)
        result as InboundEnrollHandler.Result.Reply
        assertNull(result.newPeer)
        val md = (((Json.parseToJsonElement(result.envelopeJson) as JsonObject)
                   ["payload"] as JsonObject)["metadata"]) as JsonObject
        assertEquals("enroll_err", (md["kind"] as JsonPrimitive).content)
        // Token MUST be marked consumed once we authenticated it (even on
        // PROVISION_FAILED) — daemon does this; otherwise a busy-loop
        // attacker could keep retrying with the same auth-tagged blob.
        // Actually the daemon doesn't mark consumed on provision-fail; let
        // it stay live so the user can retry once the host has space.
        assertNotNull(s.lookup(tok.tokenSecret, now = 1000L))
    }

    @Test fun `enroll_ok includes the host candidate list`(@TempDir dir: Path) {
        val f = fixture()
        val s = store(dir)
        val tok = s.mint("withCandidates", 600_000L, now = 1000L)
        val blob = buildRequestBlob(f, tok.tokenSecret, ts = 1L)
        val envJson = buildInboundEnvelopeJson(f, blob)
        val candidates = listOf(
            EndpointCandidate("192.168.43.1", 51820, "lan"),
            EndpointCandidate("203.0.113.42", 51820, "stun"),
        )
        val handler = InboundEnrollHandler(s, nowMs = { 1000L }, nowSec = { 1L })
        val parsed = extractInboundEnroll(Json.parseToJsonElement(envJson))!!
        val result = handler.handle(parsed, hostState(f, candidates = candidates))
        result as InboundEnrollHandler.Result.Reply
        val md = (((Json.parseToJsonElement(result.envelopeJson) as JsonObject)
                   ["payload"] as JsonObject)["metadata"]) as JsonObject
        val key = deriveEnrollKey(f.clientPriv, f.serverPub, tok.tokenSecret)
        val ct = Base64.getDecoder().decode((md["blob"] as JsonPrimitive).content)
        val plain = secretboxDecrypt(ct, key)
        val ok = Json.decodeFromString(EnrollOkPlain.serializer(),
                                       plain!!.toString(Charsets.UTF_8))
        val cands = ok.candidates ?: error("candidates field missing")
        assertEquals(2, cands.size)
        assertEquals("192.168.43.1", cands[0].ip)
        assertEquals("lan", cands[0].kind)
    }

    @Test fun `enroll without endpoint hint omits the field`(@TempDir dir: Path) {
        val f = fixture()
        val s = store(dir)
        val tok = s.mint("noendpoint", 600_000L, now = 1000L)
        val blob = buildRequestBlob(f, tok.tokenSecret, ts = 1L)
        val envJson = buildInboundEnvelopeJson(f, blob)
        val handler = InboundEnrollHandler(s, nowMs = { 1000L }, nowSec = { 1L })
        val parsed = extractInboundEnroll(Json.parseToJsonElement(envJson))!!
        val result = handler.handle(parsed, hostState(f, endpoint = null))
        result as InboundEnrollHandler.Result.Reply
        val md = (((Json.parseToJsonElement(result.envelopeJson) as JsonObject)
                   ["payload"] as JsonObject)["metadata"]) as JsonObject
        val key = deriveEnrollKey(f.clientPriv, f.serverPub, tok.tokenSecret)
        val ct = Base64.getDecoder().decode((md["blob"] as JsonPrimitive).content)
        val plain = secretboxDecrypt(ct, key)
        val ok = Json.decodeFromString(EnrollOkPlain.serializer(),
                                       plain!!.toString(Charsets.UTF_8))
        // Daemon emits null for absent endpoint; client tolerates either.
        assertNull(ok.serverEndpointHint)
    }

    @Test fun `expired token silently ignored`(@TempDir dir: Path) {
        val f = fixture()
        val s = store(dir)
        // Mint with a 100ms TTL.
        val tok = s.mint("expiring", expiresInMs = 100L, now = 1000L)
        // Build the request well after expiry.
        val blob = buildRequestBlob(f, tok.tokenSecret, ts = 5L)
        val envJson = buildInboundEnvelopeJson(f, blob)
        val handler = InboundEnrollHandler(s, nowMs = { 5_000L }, nowSec = { 5L })
        val parsed = extractInboundEnroll(Json.parseToJsonElement(envJson))!!
        val result = handler.handle(parsed, hostState(f))
        assertTrue(result is InboundEnrollHandler.Result.Ignore,
            "expired token must yield silent ignore, got $result")
    }

    // V6.3 — dual-stack enrollment: HostState with subnetV6 allocates
    // a v6 sibling, emits comma-separated address, and surfaces
    // assignedIpV6 in the NewPeer result.

    @Test fun `V6_3 dual-stack host emits comma-separated address`(@TempDir dir: Path) {
        val f = fixture()
        val s = store(dir)
        val tok = s.mint("alice-v6", 600_000L, now = 1000L)
        val ts = 1L
        val blob = buildRequestBlob(f, tok.tokenSecret, ts)
        val envJson = buildInboundEnvelopeJson(f, blob)
        val handler = InboundEnrollHandler(s, nowMs = { 1000L }, nowSec = { ts })
        val parsed = extractInboundEnroll(Json.parseToJsonElement(envJson))!!
        val result = handler.handle(parsed, hostState(
            f,
            subnetV6 = "fd00:dead:beef::/64",
            hostIpV6 = "fd00:dead:beef::1",
        ))

        assertTrue(result is InboundEnrollHandler.Result.Reply, "got $result")
        result as InboundEnrollHandler.Result.Reply
        assertNotNull(result.newPeer)
        // V4 sibling unchanged.
        assertEquals("10.99.0.2", result.newPeer!!.assignedIp)
        // V6 sibling populated.
        assertEquals("fd00:dead:beef::2", result.newPeer.assignedIpV6,
            "v6 should be allocated when subnetV6 is set")

        // Wire-format payload — assertion against the decoded
        // EnrollOkPlain.  The `address` field must be the canonical
        // (no-whitespace) dual-stack comma-joined form so ChromeOS's
        // WG client accepts the joiner's wg-quick on import.
        val key = deriveEnrollKey(f.clientPriv, f.serverPub, tok.tokenSecret)
        val responseEnv = Json.parseToJsonElement(result.envelopeJson) as JsonObject
        val md = ((responseEnv["payload"] as JsonObject)["metadata"]) as JsonObject
        val blobOut = (md["blob"] as JsonPrimitive).content
        val ct = Base64.getDecoder().decode(blobOut)
        val plain = secretboxDecrypt(ct, key)
        val ok = Json.decodeFromString(EnrollOkPlain.serializer(),
            plain!!.toString(Charsets.UTF_8))
        assertEquals("10.99.0.2/32,fd00:dead:beef::2/128", ok.address,
            "address must be canonical (no whitespace) comma-joined dual-stack")
    }

    @Test fun `V6_3 v4-only host (no subnetV6) keeps legacy single-CIDR address`(@TempDir dir: Path) {
        // Tunnel persisted before V6.2 has subnetV6=null.  Handler
        // must still emit the single-CIDR form so v4-only joiners
        // don't see a confusing trailing comma.
        val f = fixture()
        val s = store(dir)
        val tok = s.mint("alice-legacy", 600_000L, now = 1000L)
        val ts = 1L
        val blob = buildRequestBlob(f, tok.tokenSecret, ts)
        val envJson = buildInboundEnvelopeJson(f, blob)
        val handler = InboundEnrollHandler(s, nowMs = { 1000L }, nowSec = { ts })
        val parsed = extractInboundEnroll(Json.parseToJsonElement(envJson))!!
        val result = handler.handle(parsed, hostState(f))
        assertTrue(result is InboundEnrollHandler.Result.Reply)
        result as InboundEnrollHandler.Result.Reply
        assertNull(result.newPeer!!.assignedIpV6,
            "no subnetV6 → no v6 alloc")

        val key = deriveEnrollKey(f.clientPriv, f.serverPub, tok.tokenSecret)
        val responseEnv = Json.parseToJsonElement(result.envelopeJson) as JsonObject
        val md = ((responseEnv["payload"] as JsonObject)["metadata"]) as JsonObject
        val blobOut = (md["blob"] as JsonPrimitive).content
        val ct = Base64.getDecoder().decode(blobOut)
        val plain = secretboxDecrypt(ct, key)
        val ok = Json.decodeFromString(EnrollOkPlain.serializer(),
            plain!!.toString(Charsets.UTF_8))
        assertEquals("10.99.0.2/32", ok.address,
            "legacy v4-only path stays unchanged")
    }

    @Test fun `V6_3 v6 alloc skips already-used`(@TempDir dir: Path) {
        // Allocator policy: linear scan from hostIp + 1.  With ::2
        // already in use, expect ::3.
        val f = fixture()
        val s = store(dir)
        val tok = s.mint("bob-v6", 600_000L, now = 1000L)
        val ts = 1L
        val blob = buildRequestBlob(f, tok.tokenSecret, ts)
        val envJson = buildInboundEnvelopeJson(f, blob)
        val handler = InboundEnrollHandler(s, nowMs = { 1000L }, nowSec = { ts })
        val parsed = extractInboundEnroll(Json.parseToJsonElement(envJson))!!
        val result = handler.handle(parsed, hostState(
            f,
            subnetV6 = "fd00:dead:beef::/64",
            hostIpV6 = "fd00:dead:beef::1",
            allocatedIps = setOf("10.99.0.2"),
            allocatedIpsV6 = setOf("fd00:dead:beef::2"),
        ))
        assertTrue(result is InboundEnrollHandler.Result.Reply)
        result as InboundEnrollHandler.Result.Reply
        assertEquals("10.99.0.3", result.newPeer!!.assignedIp)
        assertEquals("fd00:dead:beef::3", result.newPeer.assignedIpV6)
    }

    companion object {
        private val b64 = Base64.getEncoder()
    }
}
