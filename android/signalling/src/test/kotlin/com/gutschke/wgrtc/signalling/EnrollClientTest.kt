package com.gutschke.wgrtc.signalling

import com.goterl.lazysodium.LazySodiumJava
import com.goterl.lazysodium.SodiumJava
import kotlinx.coroutines.test.runTest
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
import okio.ByteString
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import java.util.Base64

/**
 * EnrollClient state-machine tests against an in-process MockWebServer
 * acting as the PeerJS broker. The server side controls what gets sent
 * back so we can exercise every branch of [EnrollClient.enroll].
 *
 * The crypto half of each test is real: we derive the same enroll-key
 * the daemon would, encrypt a plaintext that matches what the daemon
 * emits, and let EnrollClient decrypt it. That makes the test a
 * meaningful end-to-end check of the protocol, not just a JSON
 * shape-matcher.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class EnrollClientTest {

    @BeforeAll fun installJvmSodium() {
        Sodium.setForTest(LazySodiumJava(SodiumJava()))
    }
    @AfterAll fun restoreSodium() { Sodium.setForTest(null) }

    private lateinit var server: MockWebServer

    @BeforeEach fun startServer() {
        server = MockWebServer().also { it.start() }
    }
    @AfterEach fun stopServer() {
        // MockWebServer.shutdown() blocks for ~5s waiting for any
        // residual websocket frames; we don't care during teardown.
        try { server.shutdown() } catch (_: Exception) {}
    }

    // ─── Setup helpers ──────────────────────────────────────────────

    /** Server-side keypair (the daemon's identity). */
    private val serverKp = generateKeyPair()
    /** 32-byte token; the URI carries an URL-safe-base64 of this. */
    private val tokenBytes = ByteArray(32) { 0x42.toByte() }
    private val saltBytes = ByteArray(32) { 0x99.toByte() }

    private fun b64UrlNoPad(b: ByteArray) =
        Base64.getUrlEncoder().withoutPadding().encodeToString(b)

    private fun makeUri(brokerWs: String, expiresAt: Long? = null): EnrollUri {
        val parts = mutableListOf(
            "pk=${b64UrlNoPad(serverKp.publicKey)}",
            "salt=${b64UrlNoPad(saltBytes)}",
            "broker=${java.net.URLEncoder.encode(brokerWs, "UTF-8")}",
            "brokerkey=test",
            "token=${b64UrlNoPad(tokenBytes)}",
        )
        if (expiresAt != null) parts.add("expires=$expiresAt")
        return EnrollUri.parse("wgrtc-enroll://v1?" + parts.joinToString("&"))
    }

    /** Build the OFFER reply the daemon would send for a given (kind, ciphertext). */
    private fun fakeServerReply(kind: String, ciphertextB64: String): String {
        val obj = buildJsonObject {
            put("type", "OFFER")
            put("src", "server")
            putJsonObject("payload") {
                put("type", "data")
                put("connectionId", "dc_test")
                put("label", "dc_test")
                put("reliable", false)
                put("serialization", "binary")
                putJsonObject("sdp") {
                    put("sdp", "stub")
                    put("type", "offer")
                }
                putJsonObject("metadata") {
                    put("v", PROTOCOL_VERSION)
                    put("kind", kind)
                    put("blob", ciphertextB64)
                }
            }
        }
        return obj.toString()
    }

    /**
     * Drives the broker side: when the client connects, send `OPEN`
     * immediately; when the client sends a message, invoke [onClientMsg]
     * with the parsed envelope so the test can decide the response.
     */
    private fun queueBrokerScript(
        onClientMsg: (envelope: JsonObject, ws: WebSocket) -> Unit,
        sendOpen: Boolean = true,
    ) {
        val listener = object : WebSocketListener() {
            override fun onOpen(ws: WebSocket, response: okhttp3.Response) {
                if (sendOpen) ws.send("""{"type":"OPEN"}""")
            }
            override fun onMessage(ws: WebSocket, text: String) {
                val env = Json.parseToJsonElement(text) as JsonObject
                onClientMsg(env, ws)
            }
            // Mirror the close back so MockWebServer's shutdown sees a
            // cleanly-terminated connection. Without this it polls for
            // 5 s before giving up.
            override fun onClosing(ws: WebSocket, code: Int, reason: String) {
                ws.close(code, reason)
            }
        }
        server.enqueue(MockResponse().withWebSocketUpgrade(listener))
    }

    // ─── Tests ──────────────────────────────────────────────────────

    @Test fun `expired URI fails locally without opening a websocket`() = runTest {
        // No server queued — if EnrollClient tried to connect, the test
        // hangs / times out instead of returning Failed("token expired
        // locally") immediately.
        val uri = makeUri("ws://127.0.0.1:1/peerjs", expiresAt = 1L) // 1970
        val r = EnrollClient(deviceLabel = "test").enroll(uri, "alice", timeoutMillis = 5_000L)
        assertTrue(r is EnrollResult.Failed)
        assertEquals("token expired locally", (r as EnrollResult.Failed).reason)
    }

    @Test fun `happy path returns Ok with decrypted plaintext`() = runTest {
        // Daemon's plaintext shape — fields the client will round-trip.
        val plain = """
            {"v":1,"ts":1700000000,"address":"10.0.0.5/32",
             "server_pubkey":"SP","server_endpoint_hint":"1.2.3.4:51820","name":"alice"}
        """.trimIndent().replace(Regex("\\s+"), " ")

        queueBrokerScript({ env, ws ->
            // Decrypt the client's ENROLL to recover the keypair the
            // daemon would have used to encrypt ENROLL_OK.
            val md = (env["payload"] as JsonObject)["metadata"] as JsonObject
            val clientPubB64 = (md["client_pub"] as JsonPrimitive).content
            val clientPub = Base64.getDecoder().decode(clientPubB64)
            val k = deriveEnrollKey(serverKp.privateKey, clientPub, tokenBytes)
            val ct = secretboxEncrypt(plain.toByteArray(Charsets.UTF_8), k)
            ws.send(fakeServerReply("enroll_ok", Base64.getEncoder().encodeToString(ct)))
        })

        val uri = makeUri("ws://127.0.0.1:${server.port}/peerjs")
        val r = EnrollClient(deviceLabel = "test").enroll(uri, "alice", timeoutMillis = 5_000L)
        assertTrue(r is EnrollResult.Ok, "got $r")
        val ok = (r as EnrollResult.Ok).plaintext
        assertEquals("10.0.0.5/32", ok.address)
        assertEquals("1.2.3.4:51820", ok.serverEndpointHint)
        assertEquals("alice", ok.name)
        assertEquals(32, r.clientPubKey.size)
        assertEquals(32, r.clientPrivKey.size)
    }

    @Test fun `enroll_err returns Err with code preserved`() = runTest {
        val plain = """{"v":1,"ts":0,"code":"TOKEN_USED","note":"already consumed"}"""

        queueBrokerScript({ env, ws ->
            val md = (env["payload"] as JsonObject)["metadata"] as JsonObject
            val clientPubB64 = (md["client_pub"] as JsonPrimitive).content
            val clientPub = Base64.getDecoder().decode(clientPubB64)
            val k = deriveEnrollKey(serverKp.privateKey, clientPub, tokenBytes)
            val ct = secretboxEncrypt(plain.toByteArray(Charsets.UTF_8), k)
            ws.send(fakeServerReply("enroll_err", Base64.getEncoder().encodeToString(ct)))
        })

        val uri = makeUri("ws://127.0.0.1:${server.port}/peerjs")
        val r = EnrollClient(deviceLabel = "test").enroll(uri, "alice", timeoutMillis = 5_000L)
        assertTrue(r is EnrollResult.Err, "got $r")
        assertEquals("TOKEN_USED", (r as EnrollResult.Err).plaintext.code)
        assertEquals("already consumed", r.plaintext.note)
    }

    @Test fun `decryption failure (wrong key) returns Failed decryption failed`() = runTest {
        queueBrokerScript({ _, ws ->
            // Encrypt with junk that the client can't derive — simulates
            // a server that's responding to the wrong tunnel or has
            // been tampered with.
            val junkKey = ByteArray(32) { 0x77.toByte() }
            val ct = secretboxEncrypt("nope".toByteArray(), junkKey)
            ws.send(fakeServerReply("enroll_ok", Base64.getEncoder().encodeToString(ct)))
        })
        val uri = makeUri("ws://127.0.0.1:${server.port}/peerjs")
        val r = EnrollClient(deviceLabel = "test").enroll(uri, "alice", timeoutMillis = 5_000L)
        assertTrue(r is EnrollResult.Failed, "got $r")
        assertEquals("decryption failed", (r as EnrollResult.Failed).reason)
    }

    @Test fun `malformed blob (non-base64) returns Failed malformed blob`() = runTest {
        queueBrokerScript({ _, ws ->
            ws.send(fakeServerReply("enroll_ok", "!!!not-base64!!!"))
        })
        val uri = makeUri("ws://127.0.0.1:${server.port}/peerjs")
        val r = EnrollClient(deviceLabel = "test").enroll(uri, "alice", timeoutMillis = 5_000L)
        assertTrue(r is EnrollResult.Failed, "got $r")
        assertEquals("malformed blob", (r as EnrollResult.Failed).reason)
    }

    @Test fun `timeout fires when server never replies`() = runTest {
        // OPEN sent but no reply to ENROLL — exercise the
        // withTimeoutOrNull branch.
        queueBrokerScript({ _, _ -> /* deliberately silent */ })
        val uri = makeUri("ws://127.0.0.1:${server.port}/peerjs")
        val r = EnrollClient(deviceLabel = "test").enroll(uri, "alice", timeoutMillis = 1_000L)
        assertTrue(r is EnrollResult.Failed, "got $r")
        assertEquals("timeout", (r as EnrollResult.Failed).reason)
    }

    @Test fun `client only sends after broker emits OPEN`() = runTest {
        // If the server never sends OPEN, the client should NOT send
        // its ENROLL — the daemon's broker contract requires waiting
        // for the OPEN frame.
        var receivedFromClient = false
        queueBrokerScript(
            sendOpen = false,
            onClientMsg = { _, _ -> receivedFromClient = true },
        )
        val uri = makeUri("ws://127.0.0.1:${server.port}/peerjs")
        EnrollClient(deviceLabel = "test").enroll(uri, "alice", timeoutMillis = 1_000L)
        assertFalse(receivedFromClient,
            "client sent ENROLL before receiving OPEN; broker contract violated")
    }

    @Test fun `connection failure returns Failed with diagnostic`() = runTest {
        // Bind to a port nothing is listening on; connect must fail fast.
        val deadPort = server.port // first capture a port...
        server.shutdown() // ...then kill the listener.
        val uri = makeUri("ws://127.0.0.1:$deadPort/peerjs")
        val r = EnrollClient(deviceLabel = "test").enroll(uri, "alice", timeoutMillis = 2_000L)
        assertTrue(r is EnrollResult.Failed, "got $r")
        // We don't pin the exact message — okhttp wording differs across
        // versions — but it must NOT be a misleading "timeout" or the
        // user can't tell the daemon is unreachable from "daemon up but
        // slow".
        val reason = (r as EnrollResult.Failed).reason
        assertNotEquals("timeout", reason)
    }
}
