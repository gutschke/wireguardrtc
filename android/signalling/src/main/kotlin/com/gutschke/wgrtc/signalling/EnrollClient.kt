package com.gutschke.wgrtc.signalling

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonObject
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import java.security.SecureRandom
import java.util.Base64
import java.util.concurrent.TimeUnit
import kotlin.coroutines.resume

/** Sealed result of a single enrollment attempt. See PLAN §4.4. */
sealed class EnrollResult {
    /** Server accepted; tunnel config attached. */
    data class Ok(
        val plaintext: EnrollOkPlain,
        val clientPubKey: ByteArray,
        val clientPrivKey: ByteArray,
    ) : EnrollResult()

    /**
     * Server returned an authenticated error (token already used,
     * provisioning failed, etc.). This is the user-noticing path —
     * UI should surface it prominently.
     */
    data class Err(val plaintext: EnrollErrPlain) : EnrollResult()

    /** Network / WebSocket / decryption / timeout failure. */
    data class Failed(val reason: String) : EnrollResult()
}

/**
 * One-shot enrollment client. Uses a freshly-generated keypair (which
 * becomes the client's WireGuard identity if enrollment succeeds) so
 * private-key material never leaves this device.
 *
 * The okhttp transport is internal to this module — callers don't
 * need okhttp on their classpath. If you want to inject a custom
 * client (proxy, custom DNS, etc.), use the `internal` constructor
 * defined within this module.
 */
class EnrollClient @JvmOverloads constructor(
    private val deviceLabel: String = "android-wgrtc",
) {
    private val httpClient: OkHttpClient =
        OkHttpClient.Builder()
            .pingInterval(30, TimeUnit.SECONDS)
            // 10 s default is the right user-facing budget — anything
            // longer keeps the user staring at a frozen UI when the
            // tunnel is genuinely never going to come up. If the
            // broker can't be reached in 10 s on a healthy network,
            // we want to fail fast with a clear error.
            .connectTimeout(10, TimeUnit.SECONDS)
            // Defense-in-depth: lazy SocketFactory that re-reads the
            // BrokerNetworkPin at every createSocket() call. Critical
            // that this is lazy — okhttp clients constructed at
            // app-startup time would otherwise capture a null pin
            // (the underlying registerDefaultNetworkCallback hasn't
            // delivered its first onAvailable yet) and stay stuck on
            // the default factory forever. See BrokerNetworkPin's
            // doc for the rationale and the case where it doesn't
            // help.
            .socketFactory(BrokerNetworkPin.lazySocketFactory)
            // Custom Dns wrapper logs the resolved addresses so a
            // "broker reachable from shell but not okhttp" mystery
            // can be diagnosed from logcat alone. Useful at the rate
            // of one log line per enrollment attempt — modest noise.
            .dns(object : okhttp3.Dns {
                override fun lookup(hostname: String): List<java.net.InetAddress> {
                    val t0 = System.currentTimeMillis()
                    return try {
                        val result = okhttp3.Dns.SYSTEM.lookup(hostname)
                        Log.i("wgrtc-dns",
                            "lookup($hostname) in " +
                            "${System.currentTimeMillis() - t0}ms -> " +
                            result.joinToString(",") { it.hostAddress ?: "?" })
                        result
                    } catch (e: java.net.UnknownHostException) {
                        Log.w("wgrtc-dns",
                            "lookup($hostname) failed in " +
                            "${System.currentTimeMillis() - t0}ms: ${e.message}")
                        throw e
                    }
                }
            })
            .build()


    /**
     * Run a single ENROLL/ENROLL_OK round-trip. Times out after
     * [timeoutMillis] (default 15 s — okhttp connectTimeout 10 s
     * plus headroom for the broker OPEN, ENROLL send, and daemon
     * response on a healthy network). If we hit this ceiling, the
     * tunnel isn't coming up; surface the error to the user fast
     * instead of leaving them staring at a frozen UI.
     *
     * @param hint a human-readable name for the new peer; the server's
     * admin will see this in `wg show` and in any provisioning logs.
     */
    suspend fun enroll(
        uri: EnrollUri,
        hint: String,
        timeoutMillis: Long = 15_000L,
    ): EnrollResult {
        if (uri.expiresAt != null && System.currentTimeMillis() / 1000 > uri.expiresAt) {
            return EnrollResult.Failed("token expired locally")
        }

        // Fresh keypair per enrollment — used both for the protocol
        // and (on success) as the WireGuard identity.
        val keypair = generateKeyPair()
        val clientPubB64 = b64StdEncode(keypair.publicKey)

        val finalKey = deriveEnrollKey(
            keypair.privateKey, uri.serverPub, uri.token
        )

        val plaintextJson = JSON.encodeToString(
            kotlinx.serialization.serializer<EnrollRequestPlain>(),
            EnrollRequestPlain(
                timestamp = System.currentTimeMillis() / 1000,
                tokenCheck = b64StdEncode(uri.token),
                hint = hint,
                device = deviceLabel,
            )
        )
        val ciphertext = secretboxEncrypt(plaintextJson.toByteArray(Charsets.UTF_8), finalKey)
        val ciphertextB64 = b64StdEncode(ciphertext)

        val ourId = routingId(clientPubB64, uri.salt)
        val dstId = routingId(b64StdEncode(uri.serverPub), uri.salt)

        val envelope = buildEnrollEnvelope(dstId, clientPubB64, ciphertextB64)

        val brokerUri = buildBrokerUri(uri.brokerWss, uri.brokerKey, ourId)

        return withContext(Dispatchers.IO) {
            // App-wide per-broker rate limit — protects the public
            // PeerJS broker from a burst of enrollment WSS-opens
            // (user retries on transient errors, etc.).
            BrokerConnectionLimiter.INSTANCE.acquire(uri.brokerWss)
            withTimeoutOrNull(timeoutMillis) {
                runEnrollExchange(brokerUri, envelope, finalKey, keypair)
            } ?: EnrollResult.Failed("timeout")
        }
    }

    private suspend fun runEnrollExchange(
        brokerUri: String,
        envelope: JsonElement,
        finalKey: ByteArray,
        keypair: KeyPair,
    ): EnrollResult = suspendCancellableCoroutine { cont ->
        val request = Request.Builder().url(brokerUri).build()
        var settled = false
        val started = System.currentTimeMillis()
        fun elapsed() = System.currentTimeMillis() - started
        fun settle(r: EnrollResult) {
            if (!settled) { settled = true; cont.resume(r) }
        }
        Log.i("wgrtc-enroll", "opening broker WSS to ${request.url}")

        val ws = httpClient.newWebSocket(request, object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: Response) {
                Log.i("wgrtc-enroll",
                    "WSS onOpen after ${elapsed()}ms (HTTP ${response.code}); " +
                    "waiting for broker OPEN frame")
            }

            override fun onMessage(webSocket: WebSocket, text: String) {
                val msg = try {
                    Json.parseToJsonElement(text)
                } catch (_: Exception) {
                    return
                }
                val type = (msg as? JsonObject)?.get("type")
                if (type is JsonPrimitive && type.content == "OPEN") {
                    // Broker session ready — send our ENROLL.
                    Log.i("wgrtc-enroll",
                        "broker OPEN at ${elapsed()}ms; sending ENROLL envelope")
                    webSocket.send(envelope.toString())
                    return
                }
                val resp = extractEnrollResponse(msg) ?: return
                val (kind, blobB64) = resp
                Log.i("wgrtc-enroll",
                    "broker delivered $kind at ${elapsed()}ms")
                val cipher = try {
                    Base64.getDecoder().decode(blobB64)
                } catch (_: Exception) {
                    settle(EnrollResult.Failed("malformed blob")); return
                }
                val plain = secretboxDecrypt(cipher, finalKey)
                if (plain == null) {
                    settle(EnrollResult.Failed("decryption failed")); return
                }
                val plainStr = plain.toString(Charsets.UTF_8)
                if (kind == "enroll_ok") {
                    val ok = try {
                        JSON.decodeFromString(EnrollOkPlain.serializer(), plainStr)
                    } catch (e: Exception) {
                        settle(EnrollResult.Failed("malformed ok: ${e.message}")); return
                    }
                    settle(EnrollResult.Ok(ok, keypair.publicKey, keypair.privateKey))
                } else {
                    val err = try {
                        JSON.decodeFromString(EnrollErrPlain.serializer(), plainStr)
                    } catch (e: Exception) {
                        settle(EnrollResult.Failed("malformed err: ${e.message}")); return
                    }
                    settle(EnrollResult.Err(err))
                }
                webSocket.close(1000, "done")
            }

            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                Log.w("wgrtc-enroll",
                    "WSS onFailure at ${elapsed()}ms: ${t.javaClass.simpleName}: ${t.message} " +
                    "(response=${response?.code})")
                settle(EnrollResult.Failed(t.message ?: t.javaClass.simpleName))
            }

            override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                Log.i("wgrtc-enroll",
                    "WSS onClosed at ${elapsed()}ms: code=$code reason=$reason")
                if (!settled) settle(EnrollResult.Failed("ws closed: $code $reason"))
            }
        })

        cont.invokeOnCancellation { ws.cancel() }
    }

    private fun buildBrokerUri(broker: String, key: String, ourId: String): String {
        val sep = if ('?' in broker) "&" else "?"
        val nonce = ByteArray(8).also { SecureRandom().nextBytes(it) }
            .joinToString("") { String.format("%02x", it) }
        return "$broker${sep}key=$key&id=$ourId&token=$nonce&version=1.5.2"
    }

    private fun b64StdEncode(b: ByteArray): String =
        Base64.getEncoder().encodeToString(b)
}
