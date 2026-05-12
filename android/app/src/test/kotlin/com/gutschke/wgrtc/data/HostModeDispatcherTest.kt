package com.gutschke.wgrtc.data

import com.goterl.lazysodium.LazySodiumJava
import com.goterl.lazysodium.SodiumJava
import com.gutschke.wgrtc.signalling.PROTOCOL_VERSION
import com.gutschke.wgrtc.signalling.Sodium
import com.gutschke.wgrtc.signalling.buildEnrollEnvelope
import com.gutschke.wgrtc.signalling.deriveEnrollKey
import com.gutschke.wgrtc.signalling.pubKeyFromPrivate
import com.gutschke.wgrtc.signalling.routingId
import com.gutschke.wgrtc.signalling.secretboxEncrypt
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceUntilIdle
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
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.atomic.AtomicReference

/**
 * Tests for [HostModeDispatcher] — the glue between
 * [com.gutschke.wgrtc.signalling.OfferListener]'s host-mode `onPayload`
 * callback and [InboundEnrollHandler]. Verifies dispatch ordering
 * (persist → reconfig → respond), silent-ignore on non-enroll
 * messages, and that handler `Ignore` results don't trigger any
 * side effects.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class HostModeDispatcherTest {

    @BeforeAll fun installJvmSodium() {
        Sodium.setForTest(LazySodiumJava(SodiumJava()))
    }
    @AfterAll fun restoreSodium() { Sodium.setForTest(null) }

    private val rng = SecureRandom()

    private data class Fixture(
        val serverPriv: ByteArray, val serverPub: ByteArray, val serverPubB64: String,
        val clientPriv: ByteArray, val clientPub: ByteArray, val clientPubB64: String,
        val saltBytes: ByteArray, val srcId: String,
    )

    private fun fixture(): Fixture {
        val sp = ByteArray(32).also { rng.nextBytes(it) }
        val spub = pubKeyFromPrivate(sp)
        val cp = ByteArray(32).also { rng.nextBytes(it) }
        val cpub = pubKeyFromPrivate(cp)
        val salt = ByteArray(32) { 0xCC.toByte() }
        val cpubB64 = Base64.getEncoder().encodeToString(cpub)
        return Fixture(sp, spub, Base64.getEncoder().encodeToString(spub),
                       cp, cpub, cpubB64, salt, routingId(cpubB64, salt))
    }

    private fun store(dir: Path) = PendingTokensStore(File(dir.toFile(), "pending.json"))

    private fun hostState(f: Fixture, allocatedIps: Set<String> = emptySet()) =
        InboundEnrollHandler.HostState(
            serverPrivBytes = f.serverPriv,
            serverPubB64 = f.serverPubB64,
            listenPort = 51820,
            hostIp = "10.99.0.1",
            subnet = "10.99.0.0/24",
            saltBytes = f.saltBytes,
            publicEndpointHint = "192.0.2.1:51820",
            candidates = emptyList(),
            allocatedIps = allocatedIps,
        )

    private fun buildInboundEnvelopeJson(
        f: Fixture, tokenSecret: ByteArray, ts: Long, hint: String = "alice",
    ): String {
        val tokenB64 = Base64.getEncoder().encodeToString(tokenSecret)
        val plaintext = """{"v":$PROTOCOL_VERSION,"ts":$ts,
            |"token_check":"$tokenB64","hint":"$hint","device":"test"}""".trimMargin()
            .replace("\n", "")
        val key = deriveEnrollKey(f.clientPriv, f.serverPub, tokenSecret)
        val ct = secretboxEncrypt(plaintext.toByteArray(), key)
        val blobB64 = Base64.getEncoder().encodeToString(ct)
        val env = buildEnrollEnvelope(
            dstRoutingId = "deadbeef".repeat(8),
            clientPubBase64 = f.clientPubB64,
            blobBase64 = blobB64,
        ) as JsonObject
        val withSrc = JsonObject(env.toMutableMap().apply {
            put("src", JsonPrimitive(f.srcId))
        })
        return withSrc.toString()
    }

    /** Records every callback invocation in order. */
    private class CallRecorder {
        sealed class Call {
            data class Apply(val peer: InboundEnrollHandler.NewPeer) : Call()
            data class Send(val envelope: String) : Call()
        }
        val calls = ConcurrentLinkedQueue<Call>()
        var sendResult = true
        var applyShouldFail = false
        suspend fun applyEnrollment(p: InboundEnrollHandler.NewPeer) {
            if (applyShouldFail) throw RuntimeException("apply failed")
            calls += Call.Apply(p)
        }
        suspend fun sendVia(env: String): Boolean {
            calls += Call.Send(env)
            return sendResult
        }
    }

    @Test fun `valid enroll triggers persist before send`(@TempDir dir: Path) = runBlocking {
        val f = fixture()
        val s = store(dir)
        val tok = s.mint("alice", 600_000L, now = 1000L)
        val handler = InboundEnrollHandler(s, nowMs = { 1000L }, nowSec = { 1L })
        val rec = CallRecorder()
        val dispatcher = HostModeDispatcher(
            handler = handler,
            hostStateProvider = { hostState(f) },
            applyEnrollment = rec::applyEnrollment,
            sendVia = rec::sendVia,
            scope = kotlinx.coroutines.CoroutineScope(Dispatchers.Unconfined),
        )
        val msg = Json.parseToJsonElement(buildInboundEnvelopeJson(f, tok.tokenSecret, ts = 1L))
        dispatcher.onMessage(msg)

        // With Dispatchers.Unconfined, the launched coroutine runs
        // synchronously inside onMessage. The order of calls must be
        // applyEnrollment THEN sendVia.
        assertEquals(2, rec.calls.size)
        val first = rec.calls.poll()
        val second = rec.calls.poll()
        assertTrue(first is CallRecorder.Call.Apply,
            "expected Apply first, got ${first?.javaClass?.simpleName}")
        assertTrue(second is CallRecorder.Call.Send,
            "expected Send second, got ${second?.javaClass?.simpleName}")
        // Apply called with the right peer info.
        first as CallRecorder.Call.Apply
        assertEquals(f.clientPubB64, first.peer.pubkeyB64)
        assertEquals("10.99.0.2", first.peer.assignedIp)
        assertEquals("alice", first.peer.nameHint)
    }

    @Test fun `non-enroll messages are ignored`(@TempDir dir: Path) = runBlocking {
        val f = fixture()
        val s = store(dir)
        val handler = InboundEnrollHandler(s, nowMs = { 1000L }, nowSec = { 1L })
        val rec = CallRecorder()
        val dispatcher = HostModeDispatcher(
            handler, { hostState(f) },
            rec::applyEnrollment, rec::sendVia,
            kotlinx.coroutines.CoroutineScope(Dispatchers.Unconfined),
        )
        // A signal_wake or unknown-kind frame must be silently dropped.
        val wake = Json.parseToJsonElement("""
            {"type":"OFFER","src":"abc","payload":{"metadata":
              {"v":1,"kind":"signal_wake","blob":"xx"}}}
        """.trimIndent())
        dispatcher.onMessage(wake)
        // Non-OFFER frames too.
        dispatcher.onMessage(Json.parseToJsonElement("""{"type":"OPEN"}"""))
        dispatcher.onMessage(Json.parseToJsonElement("""{"random":"junk"}"""))
        assertTrue(rec.calls.isEmpty(),
            "expected no callbacks, got ${rec.calls.toList()}")
    }

    @Test fun `enroll_err reply sends but does not persist`(@TempDir dir: Path) = runBlocking {
        // Pre-consume the token so the handler returns enroll_err
        // (TOKEN_USED) — newPeer should be null.
        val f = fixture()
        val s = store(dir)
        val tok = s.mint("collide", 600_000L, now = 1000L)
        s.consume(tok.tokenSecret, now = 1000L)
        val handler = InboundEnrollHandler(s, nowMs = { 1000L }, nowSec = { 1L })
        val rec = CallRecorder()
        val dispatcher = HostModeDispatcher(
            handler, { hostState(f) },
            rec::applyEnrollment, rec::sendVia,
            kotlinx.coroutines.CoroutineScope(Dispatchers.Unconfined),
        )
        val msg = Json.parseToJsonElement(buildInboundEnvelopeJson(f, tok.tokenSecret, ts = 1L))
        dispatcher.onMessage(msg)
        // Should send the err response but NOT call applyEnrollment.
        assertEquals(1, rec.calls.size)
        assertTrue(rec.calls.peek() is CallRecorder.Call.Send)
    }

    @Test fun `handler ignore yields no side effects`(@TempDir dir: Path) = runBlocking {
        // Mismatched src — handler returns Ignore.
        val f = fixture()
        val s = store(dir)
        val tok = s.mint("nope", 600_000L, now = 1000L)
        val handler = InboundEnrollHandler(s, nowMs = { 1000L }, nowSec = { 1L })
        val rec = CallRecorder()
        val dispatcher = HostModeDispatcher(
            handler, { hostState(f) },
            rec::applyEnrollment, rec::sendVia,
            kotlinx.coroutines.CoroutineScope(Dispatchers.Unconfined),
        )
        val tokenB64 = Base64.getEncoder().encodeToString(tok.tokenSecret)
        val pt = """{"v":$PROTOCOL_VERSION,"ts":1,"token_check":"$tokenB64",
            |"hint":"nope","device":"t"}""".trimMargin().replace("\n", "")
        val key = deriveEnrollKey(f.clientPriv, f.serverPub, tok.tokenSecret)
        val ct = secretboxEncrypt(pt.toByteArray(), key)
        val env = buildEnrollEnvelope(
            "deadbeef".repeat(8), f.clientPubB64,
            Base64.getEncoder().encodeToString(ct),
        ) as JsonObject
        // Inject WRONG src so handler returns Ignore.
        val withWrongSrc = JsonObject(env.toMutableMap().apply {
            put("src", JsonPrimitive("00000000".repeat(8)))
        })
        dispatcher.onMessage(withWrongSrc)
        assertTrue(rec.calls.isEmpty(),
            "Ignore must produce no side effects, got ${rec.calls.toList()}")
    }

    @Test fun `applyEnrollment failure aborts before send`(@TempDir dir: Path) = runBlocking {
        // If persisting / reconfiguring wg-go throws, we must NOT
        // send the OK response — a fresh client can re-enroll
        // (token still consumed but with no peer in tunnels.json
        // that's a recoverable inconsistency the host can clean up).
        val f = fixture()
        val s = store(dir)
        val tok = s.mint("a", 600_000L, now = 1000L)
        val handler = InboundEnrollHandler(s, nowMs = { 1000L }, nowSec = { 1L })
        val rec = CallRecorder().also { it.applyShouldFail = true }
        val dispatcher = HostModeDispatcher(
            handler, { hostState(f) },
            rec::applyEnrollment, rec::sendVia,
            kotlinx.coroutines.CoroutineScope(Dispatchers.Unconfined),
        )
        val msg = Json.parseToJsonElement(buildInboundEnvelopeJson(f, tok.tokenSecret, ts = 1L))
        dispatcher.onMessage(msg)
        // No send because apply threw. No assertion on call order
        // beyond "no send happened".
        assertTrue(rec.calls.none { it is CallRecorder.Call.Send },
            "send should not fire when apply throws")
    }

    @Test fun `host state is fetched fresh per request`(@TempDir dir: Path) = runBlocking {
        // Two enrollments back-to-back should see the second one
        // observe the first one's allocatedIps. The dispatcher MUST
        // call hostStateProvider() each time, not cache it.
        val f = fixture()
        val s = store(dir)
        val tok1 = s.mint("first", 600_000L, now = 1000L)
        val tok2 = s.mint("second", 600_000L, now = 1000L)
        val handler = InboundEnrollHandler(s, nowMs = { 1000L }, nowSec = { 1L })
        val allocated = AtomicReference<Set<String>>(emptySet())
        val rec = CallRecorder()
        val dispatcher = HostModeDispatcher(
            handler,
            hostStateProvider = { hostState(f, allocatedIps = allocated.get()) },
            applyEnrollment = { p ->
                rec.calls += CallRecorder.Call.Apply(p)
                // Simulate persistence: bump the allocated set.
                allocated.set(allocated.get() + p.assignedIp)
            },
            sendVia = rec::sendVia,
            scope = kotlinx.coroutines.CoroutineScope(Dispatchers.Unconfined),
        )
        val msg1 = Json.parseToJsonElement(buildInboundEnvelopeJson(f, tok1.tokenSecret, ts = 1L))
        dispatcher.onMessage(msg1)

        // For the second call we need a different client (otherwise
        // duplicate-pubkey throws inside withEnrolledPeer; but here
        // we don't hit that path because we own the apply callback
        // — but the IP allocator must see the first IP as in-use).
        val applies = rec.calls.filterIsInstance<CallRecorder.Call.Apply>()
        assertEquals(1, applies.size)
        assertEquals("10.99.0.2", applies[0].peer.assignedIp)

        // Second client.
        val f2 = fixture()
        // re-use the second token but with a different client_pub +
        // re-derived envelope (the test fixture's tok2 was minted
        // under f's pubkey context, but token_check is a fingerprint
        // of the token bytes themselves — pubkey-agnostic). We need
        // a fixture-specific blob, so fake one with f2's keys.
        val msg2 = Json.parseToJsonElement(buildInboundEnvelopeJson(f2, tok2.tokenSecret, ts = 1L))
        // BUT host state is built from `f`, not `f2` — so the handler
        // looks up the token using f.serverPriv but the envelope was
        // encrypted with f2.serverPub. That's a mismatch and would
        // be Ignore'd, defeating the test.
        //
        // Instead, just reuse f and a fresh second client keypair.
        val sp2 = ByteArray(32).also { rng.nextBytes(it) }
        val spub2 = pubKeyFromPrivate(sp2)
        val cpub2B64 = Base64.getEncoder().encodeToString(spub2)
        val tokB64 = Base64.getEncoder().encodeToString(tok2.tokenSecret)
        val pt = """{"v":$PROTOCOL_VERSION,"ts":1,"token_check":"$tokB64",
            |"hint":"second","device":"t"}""".trimMargin().replace("\n", "")
        val key2 = deriveEnrollKey(sp2, f.serverPub, tok2.tokenSecret)
        val ct2 = secretboxEncrypt(pt.toByteArray(), key2)
        val env2 = buildEnrollEnvelope(
            "deadbeef".repeat(8), cpub2B64, Base64.getEncoder().encodeToString(ct2),
        ) as JsonObject
        val withSrc2 = JsonObject(env2.toMutableMap().apply {
            put("src", JsonPrimitive(routingId(cpub2B64, f.saltBytes)))
        })
        dispatcher.onMessage(withSrc2)

        val applies2 = rec.calls.filterIsInstance<CallRecorder.Call.Apply>()
        assertEquals(2, applies2.size)
        // Second peer should get .3 (.2 already taken).
        assertEquals("10.99.0.3", applies2[1].peer.assignedIp,
            "expected fresh hostState lookup; got ${applies2[1].peer.assignedIp}")
    }
}
