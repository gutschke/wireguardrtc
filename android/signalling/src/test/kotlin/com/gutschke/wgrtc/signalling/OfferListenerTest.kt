package com.gutschke.wgrtc.signalling

import com.goterl.lazysodium.LazySodiumJava
import com.goterl.lazysodium.SodiumJava
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonObject
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import java.util.Base64

/**
 * Drives [OfferListener] against an in-process MockWebServer that
 * acts as the PeerJS broker. Each test scripts the broker's outgoing
 * frames and asserts the listener emits (or doesn't emit) the right
 * [EndpointUpdate].
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class OfferListenerTest {

    @BeforeAll fun installJvmSodium() {
        Sodium.setForTest(LazySodiumJava(SodiumJava()))
    }
    @AfterAll fun restoreSodium() { Sodium.setForTest(null) }

    private lateinit var server: MockWebServer
    private lateinit var listener: OfferListener

    @BeforeEach fun startServer() {
        server = MockWebServer().also { it.start() }
        listener = OfferListener()
    }
    @AfterEach fun stopServer() {
        kotlinx.coroutines.runBlocking { listener.stop() }
        try { server.shutdown() } catch (_: Exception) {}
    }

    // ─── helpers ─────────────────────────────────────────────────

    private val sigboxKey = ByteArray(32) { 0x33.toByte() }
    private val saltBytes = ByteArray(32) { 0xCC.toByte() }
    private val myPubB64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

    private fun encryptEndpoint(ip: String, port: Int, ts: Long = System.currentTimeMillis() / 1000): String {
        val plain = """{"v":$PROTOCOL_VERSION,"ts":$ts,
            "candidates":[{"ip":"$ip","port":$port,"kind":"stun"}]}""".trimIndent()
        val ct = secretboxEncrypt(plain.toByteArray(Charsets.UTF_8), sigboxKey)
        return Base64.getEncoder().encodeToString(ct)
    }

    private fun offerEnvelope(blob: String, kind: String? = null): String {
        val obj = buildJsonObject {
            put("type", "OFFER"); put("src", "daemon")
            putJsonObject("payload") {
                put("type", "data"); put("connectionId", "dc_x")
                put("label", "dc_x"); put("reliable", false)
                put("serialization", "binary")
                putJsonObject("sdp") { put("sdp", "stub"); put("type", "offer") }
                putJsonObject("metadata") {
                    put("v", PROTOCOL_VERSION)
                    if (kind != null) put("kind", kind)
                    put("blob", blob)
                }
            }
        }
        return obj.toString()
    }

    /** Drive the broker side: wait for connection, send OPEN, then
     * invoke [onOpened] (typically to send OFFERs). Mirrors the
     * pattern used in EnrollClientTest. */
    private fun queueBrokerScript(
        sendOpen: Boolean = true,
        onOpened: (WebSocket) -> Unit = {},
    ) {
        val l = object : WebSocketListener() {
            override fun onOpen(ws: WebSocket, response: okhttp3.Response) {
                if (sendOpen) {
                    ws.send("""{"type":"OPEN"}""")
                    onOpened(ws)
                }
            }
            override fun onClosing(ws: WebSocket, code: Int, reason: String) {
                ws.close(code, reason)
            }
        }
        server.enqueue(MockResponse().withWebSocketUpgrade(l))
    }

    private fun brokerWss() = "ws://${server.hostName}:${server.port}/peerjs"

    // ─── tests ───────────────────────────────────────────────────

    @Test fun `emits EndpointUpdate on signalling OFFER`() = runBlocking {
        queueBrokerScript { ws ->
            val blob = encryptEndpoint("198.51.100.10", 51820)
            ws.send(offerEnvelope(blob))
        }
        listener.start(this, brokerWss(), "test", myPubB64, saltBytes, sigboxKey)
        val update = withTimeoutOrNull(5_000) { listener.updates.first() }
        assertNotNull(update, "no update emitted")
        assertEquals("198.51.100.10", update!!.ip)
        assertEquals(51820, update.port)
    }

    @Test fun `ignores enrolment OFFERs`() = runBlocking {
        // The listener is only for signalling; enrolment OFFERs ride
        // in the same envelope but are discriminated by metadata.kind.
        queueBrokerScript { ws ->
            val blob = encryptEndpoint("198.51.100.10", 51820)
            ws.send(offerEnvelope(blob, kind = "enroll_ok"))
        }
        listener.start(this, brokerWss(), "test", myPubB64, saltBytes, sigboxKey)
        val update = withTimeoutOrNull(2_000) { listener.updates.first() }
        assertNull(update, "enrolment OFFER should not produce an EndpointUpdate")
    }

    @Test fun `ignores OFFER with wrong key (silent)`() = runBlocking {
        val wrongKey = ByteArray(32) { 0x77.toByte() }
        queueBrokerScript { ws ->
            val plain = """{"v":1,"ts":${System.currentTimeMillis()/1000},
                            "ip":"203.0.113.99","port":51820}""".trimIndent()
            val ct = secretboxEncrypt(plain.toByteArray(), wrongKey)
            ws.send(offerEnvelope(Base64.getEncoder().encodeToString(ct)))
        }
        listener.start(this, brokerWss(), "test", myPubB64, saltBytes, sigboxKey)
        val update = withTimeoutOrNull(2_000) { listener.updates.first() }
        assertNull(update)
    }

    @Test fun `routing-id is exposed and matches SHA256(pub salt)`() = runBlocking {
        queueBrokerScript() // session opens, no OFFERs
        listener.start(this, brokerWss(), "test", myPubB64, saltBytes, sigboxKey)
        // tiny wait so the websocket actually connects + we're past
        // the broker's OPEN frame. Listener is non-blocking, so we
        // poll for `ourId` to be set by start().
        val expected = routingId(myPubB64, saltBytes)
        val deadline = System.currentTimeMillis() + 2_000
        while (listener.ourId == null && System.currentTimeMillis() < deadline) {
            kotlinx.coroutines.delay(20)
        }
        assertEquals(expected, listener.ourId)
    }

    @Test fun `multiple OFFERs are all delivered`() = runBlocking {
        // The flow has buffer = 16 with DROP_OLDEST; bursts up to
        // that size should arrive intact. Test with three.
        queueBrokerScript { ws ->
            ws.send(offerEnvelope(encryptEndpoint("203.0.113.1", 51820)))
            ws.send(offerEnvelope(encryptEndpoint("203.0.113.2", 51821)))
            ws.send(offerEnvelope(encryptEndpoint("203.0.113.3", 51822)))
        }
        listener.start(this, brokerWss(), "test", myPubB64, saltBytes, sigboxKey)
        val collected = mutableListOf<EndpointUpdate>()
        withTimeoutOrNull(5_000) {
            listener.updates.collect {
                collected.add(it)
                if (collected.size == 3) return@collect
            }
        }
        assertEquals(3, collected.size, "got: $collected")
        assertEquals("203.0.113.1", collected[0].ip)
        assertEquals(51822, collected[2].port)
    }

    @Test fun `stop is idempotent and safe`() = runBlocking {
        queueBrokerScript()
        listener.start(this, brokerWss(), "test", myPubB64, saltBytes, sigboxKey)
        listener.stop()
        listener.stop() // second call must not throw
        assertNull(listener.ourId)
    }

    @Test fun `not started means no ourId`() {
        assertNull(listener.ourId)
    }

    // the wormhole SAS race regression. WormholeJoin/HostController's
    // `userConfirm()` calls `session.sendConfirmWithInfo(...)` (which enqueues
    // a SAS_CONFIRM frame onto okhttp's outbound queue) and then, if the
    // peer's confirm was already buffered, synchronously runs
    // `verifyAndAdvance` → `teardown()` → `session.close()` →
    // `OfferListener.stop()`. If stop() used `ws.cancel()` the queued frame
    // would be discarded before okhttp's writer thread serialized it onto the
    // wire, and the peer would sit in AwaitingPeerConfirm forever.
    //
    // This test reproduces the race: enqueue N messages back-to-back, then
    // call stop() immediately. The server must receive all N. With the
    // pre-fix `ws.cancel()` semantics the count comes up short; with the
    // graceful `ws.close()` fix every message arrives.
    @Test fun `stop flushes queued sends - wormhole confirm race`() = runBlocking {
        val received = java.util.concurrent.CopyOnWriteArrayList<String>()
        val handshakeLatch = java.util.concurrent.CountDownLatch(1)
        val l = object : WebSocketListener() {
            override fun onOpen(ws: WebSocket, response: okhttp3.Response) {
                ws.send("""{"type":"OPEN"}""")
                handshakeLatch.countDown()
            }
            override fun onMessage(ws: WebSocket, text: String) {
                if (text.startsWith("""{"type":"OPEN""")) return // self-echo guard
                received.add(text)
            }
            override fun onClosing(ws: WebSocket, code: Int, reason: String) {
                // Graceful close path: server echoes the close back. This
                // lets okhttp's client-side writer thread finish flushing
                // before tearing down the socket.
                ws.close(code, reason)
            }
        }
        server.enqueue(MockResponse().withWebSocketUpgrade(l))

        listener.start(this, brokerWss(), "test", myPubB64, saltBytes, sigboxKey)
        // Wait for the OPEN frame to land so sendThrough won't early-return.
        val openOk = withTimeoutOrNull(5_000) {
            handshakeLatch.await(5, java.util.concurrent.TimeUnit.SECONDS)
        }
        assertTrue(openOk == true, "session never opened")
        // Belt-and-braces — wait for the session-open flag too.
        listener.awaitSessionOpen(2_000)

        // Send a burst, then immediately request stop. In pre-fix code
        // ws.cancel() races okhttp's writer and drops some/all messages.
        val n = 50
        for (i in 0 until n) {
            val ok = listener.sendThrough("""{"seq":$i,"payload":"x"}""")
            assertTrue(ok, "sendThrough refused at i=$i")
        }
        listener.stop()

        // Give okhttp's writer + the MockWebServer dispatcher a generous
        // window to deliver every queued frame the close handshake should
        // be flushing. With graceful close all 50 frames arrive; with
        // cancel() they don't.
        val deadline = System.currentTimeMillis() + 5_000
        while (received.size < n && System.currentTimeMillis() < deadline) {
            kotlinx.coroutines.delay(20)
        }
        assertEquals(n, received.size,
            "stop() dropped queued frames — expected $n, got ${received.size}")
    }
}
