package com.gutschke.wgrtc.signalling

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import java.security.SecureRandom
import java.util.concurrent.TimeUnit

/**
 * Long-lived PeerJS connection that listens for inbound signalling
 * OFFERs from the daemon and emits each decoded [EndpointUpdate] on
 * [updates].
 *
 * Mirrors the daemon's `PeerJSClient` behaviour:
 * - registers under our routing-id (`SHA256(myPubB64 ‖ salt)`)
 * - waits for the broker's `{"type":"OPEN"}` before treating the
 * session as live
 * - heartbeats every 5 s (matches the daemon's `PEERJS_HEARTBEAT`
 * constant — the public PeerJS broker drops idle sockets faster)
 * - reconnects with exponential backoff capped at [MAX_BACKOFF_MS]
 *
 * This class does **not** know about WireGuard; on-receipt of an
 * [EndpointUpdate] the consumer (typically the app's ViewModel)
 * decides what to do with it (rewrite the tunnel's `Endpoint = `
 * line, push it to the kernel via `Backend.setState(UP, ...)`, etc).
 *
 * Lifecycle: call [start] inside a CoroutineScope you own; call
 * [stop] when you no longer want to receive updates. Idempotent —
 * calling start twice is a no-op (the second call's parameters are
 * ignored), calling stop twice is a no-op. The same instance can be
 * re-started after stop.
 */
class OfferListener {
    /** okhttp client. Internal so callers in modules that don't
     * depend on okhttp directly (the `app` module) can still
     * construct an [OfferListener] with `OfferListener()`. Tests
     * inside `signalling/` can replace this via [setHttpClientForTest]. */
    private var httpClient: OkHttpClient =
        OkHttpClient.Builder()
            .pingInterval(30, TimeUnit.SECONDS)
            .connectTimeout(10, TimeUnit.SECONDS)
            // Lazy pin SocketFactory — see BrokerNetworkPin's doc
            // and the matching note in EnrollClient.
            .socketFactory(BrokerNetworkPin.lazySocketFactory)
            .build()

    /** Test seam — see the [httpClient] note. */
    @kotlin.jvm.JvmName("setHttpClientForTest")
    internal fun setHttpClientForTest(client: OkHttpClient) {
        httpClient = client
    }
    /**
     * Stream of decrypted endpoint updates. Replay = 0 (we only
     * deliver to live collectors; missed updates are inherent to the
     * protocol — the next OFFER carries the latest IP), buffer = 16
     * to absorb short-lived backpressure without blocking the
     * websocket reader.
     */
    private val _updates = MutableSharedFlow<EndpointUpdate>(
        replay = 0, extraBufferCapacity = 16,
        onBufferOverflow = BufferOverflow.DROP_OLDEST,
    )
    val updates: SharedFlow<EndpointUpdate> = _updates.asSharedFlow()

    /**
     * Full multi-candidate updates — emits the entire ranked list the
     * sender supplied (Step C+). [updates] still emits the
     * first-valid-candidate single value for back-compat with the
     * legacy listener consumers (the persisted-Endpoint rewriter).
     * Step F's [ConnectionRunner] consumes [candidateUpdates] to race
     * the full list.
     *
     * `replay = 1` so a freshly-launched ConnectionRunner can pick up
     * the most recent candidate list without waiting for a fresh
     * OFFER. This is the "cache" that makes Connect-while-listener-
     * already-running fast.
     */
    private val _candidateUpdates = MutableSharedFlow<List<EndpointUpdate>>(
        replay = 1, extraBufferCapacity = 16,
        onBufferOverflow = BufferOverflow.DROP_OLDEST,
    )
    val candidateUpdates: SharedFlow<List<EndpointUpdate>> =
        _candidateUpdates.asSharedFlow()

    private val mutex = Mutex()
    private var runJob: Job? = null
    private var scope: CoroutineScope? = null
    @Volatile private var ws: WebSocket? = null

    /** Current registration's routing-id, exposed for diagnostics.
     * Null when not running. */
    @Volatile var ourId: String? = null
        private set

    /** True iff a session is currently OPEN at the broker (we've
     * received the JSON `{"type":"OPEN"}` frame and the socket has
     * not yet been closed/failed). Reset to false on each new
     * session attempt and on close/failure.
     *
     * Exposed as a [MutableStateFlow] so [awaitSessionOpen] can
     * suspend until it flips true without polling. */
    private val _sessionOpen = MutableStateFlow(false)

    /**
     * Send a single JSON envelope through the listener's live broker
     * WSS. Returns false if the session isn't currently OPEN, the
     * underlying socket reference is null, or okhttp's send-queue
     * refused the frame (e.g. socket already closing).
     *
     * Intended for client-initiated `signal_wake` envelopes (see
     * [OfferSender]) and any other small fire-and-forget message that
     * benefits from riding the listener's already-pinned, already-
     * registered session — avoiding a separate broker connect (which
     * would cost a round-trip plus a [BrokerConnectionLimiter] wait
     * and, more importantly, would register under a different broker
     * id, breaking the daemon's `src_id == routing_id(peer_pub, salt)`
     * dispatch path).
     */
    fun sendThrough(envelope: String): Boolean {
        if (!_sessionOpen.value) return false
        val socket = ws ?: return false
        return socket.send(envelope)
    }

    /**
     * Suspend until the session is OPEN, or [timeoutMs] elapses.
     * Returns true if OPEN within the timeout, false on timeout.
     * Cooperatively cancellable.
     */
    suspend fun awaitSessionOpen(timeoutMs: Long): Boolean {
        if (_sessionOpen.value) return true
        return withTimeoutOrNull(timeoutMs) {
            _sessionOpen.first { it }
            true
        } ?: false
    }

    /**
     * Begin listening. [brokerWss] should be the same `wss://…` URL
     * the daemon is configured with. [brokerKey] is the PeerJS API
     * key. [myPubBase64] is our WireGuard public key (44-char
     * std-base64). [saltBytes] is the daemon's salt (decoded from the
     * URI's `salt=` URL-safe-base64 field). [sigboxKey] is the
     * 32-byte X25519+BLAKE2b key derived via [deriveSigboxKey].
     *
     * The supplied [parentScope] owns the listener's coroutines —
     * cancelling the scope (or calling [stop]) terminates the
     * websocket and the heartbeat loop cleanly.
     */
    suspend fun start(
        parentScope: CoroutineScope,
        brokerWss: String,
        brokerKey: String,
        myPubBase64: String,
        saltBytes: ByteArray,
        sigboxKey: ByteArray,
        rejectIfInside: List<String> = emptyList(),
    ) = mutex.withLock {
        if (runJob?.isActive == true) return@withLock
        val rid = routingId(myPubBase64, saltBytes)
        ourId = rid
        val ownScope = CoroutineScope(parentScope.coroutineContext + SupervisorJob())
        scope = ownScope
        // Peer-mode payload handler: decrypt with our per-tunnel sigbox
        // key and emit endpoint candidates to subscribers. Callable
        // from the WS reader thread (uses tryEmit, no suspending).
        val onPayload: (JsonElement) -> Unit = { msg ->
            val blob = extractSignallingOffer(msg)
            if (blob != null) {
                val list = decryptEndpointCandidates(
                    sigboxKey, blob, rejectIfInside = rejectIfInside,
                )
                if (list == null) {
                    Log.w("wgrtc-listener",
                        "OFFER blob received but decrypt/parse failed " +
                        "(stale ts? wrong key? rejectIfInside=${rejectIfInside})")
                } else {
                    Log.i("wgrtc-listener",
                        "OFFER decrypted: ${list.size} candidates: " +
                        list.joinToString(",") { "${it.ip}:${it.port}" })
                    // tryEmit because we're on the WS reader thread.
                    // BufferOverflow.DROP_OLDEST keeps the freshest update.
                    _candidateUpdates.tryEmit(list)
                    list.firstOrNull()?.let { _updates.tryEmit(it) }
                }
            }
        }
        runJob = ownScope.launch(Dispatchers.IO) {
            runReconnectLoop(brokerWss, brokerKey, rid, onPayload)
        }
    }

    /**
     * host-mode listener (5). Same broker-WSS plumbing
     * as [start] (reconnect loop, heartbeat, sessionOpen state),
     * but instead of decrypting OFFERs with a per-tunnel sigbox
     * key, every non-control frame is passed verbatim to
     * [onPayload] so the caller can route it through the
     * [com.gutschke.wgrtc.data.InboundEnrollHandler] (or any
     * future host-mode dispatch).
     *
     * [onPayload] is invoked on the okhttp WS reader thread; it
     * MUST NOT block. Suspend work (file I/O, wg-go reconfig)
     * should be dispatched to a coroutine scope by the caller.
     */
    suspend fun startHostMode(
        parentScope: CoroutineScope,
        brokerWss: String,
        brokerKey: String,
        hostPubBase64: String,
        saltBytes: ByteArray,
        onPayload: (JsonElement) -> Unit,
    ) = startWithRoutingId(
        parentScope, brokerWss, brokerKey,
        routingId(hostPubBase64, saltBytes),
        onPayload,
    )

    /**
     * Subscribe under a pre-computed routing-id without going
     * through the WG-pubkey + salt derivation. Used by the
     * wormhole flow ([com.gutschke.wgrtc.signalling.sasRoutingIdInitiator]
     * / Responder) where the routing id is derived from the
     * wormhole code directly — neither side has the other's WG
     * pubkey yet.
     *
     * Same delivery contract as [startHostMode]: every non-control
     * payload fires [onPayload] verbatim on the okhttp WS reader
     * thread (must not block).
     */
    suspend fun startWithRoutingId(
        parentScope: CoroutineScope,
        brokerWss: String,
        brokerKey: String,
        routingId: String,
        onPayload: (JsonElement) -> Unit,
    ) = mutex.withLock {
        if (runJob?.isActive == true) return@withLock
        ourId = routingId
        val ownScope = CoroutineScope(parentScope.coroutineContext + SupervisorJob())
        scope = ownScope
        runJob = ownScope.launch(Dispatchers.IO) {
            runReconnectLoop(brokerWss, brokerKey, routingId, onPayload)
        }
    }

    suspend fun stop() = mutex.withLock {
        // Graceful close (code 1000 = NORMAL_CLOSURE) — okhttp's writer
        // thread finishes flushing the outbound queue *before* sending
        // the CLOSE frame, so any in-flight `sendThrough` survives the
        // teardown. Using `cancel()` here used to discard the queued
        // SAS_CONFIRM frame that WormholeJoin/HostController had just
        // enqueued moments earlier, leaving the peer hung in
        // AwaitingPeerConfirm forever.
        //
        // `close()` returns false if the socket was never opened, was
        // already closed, or the outbound queue is full — fall back to
        // cancel() in those edge cases so we still release resources.
        val w = ws
        ws = null
        if (w != null && !w.close(1000, "stop")) {
            w.cancel()
        }
        scope?.cancel()
        scope = null
        runJob = null
        ourId = null
        _sessionOpen.value = false
    }

    private suspend fun runReconnectLoop(
        brokerWss: String, brokerKey: String, rid: String,
        onPayload: (JsonElement) -> Unit,
    ) {
        var backoffMs = INITIAL_BACKOFF_MS
        Log.i("wgrtc-listener",
            "starting reconnect loop for $brokerWss (rid=...${rid.takeLast(8)})")
        while (kotlinx.coroutines.currentCoroutineContext()[Job]?.isActive != false) {
            // App-wide per-broker rate limit — pacifies the public
            // broker against burst connection-opens from any path
            // (listener reconnects, wakes, enrollments). Cooperatively
            // cancellable.
            BrokerConnectionLimiter.INSTANCE.acquire(brokerWss)
            val sessionStart = System.currentTimeMillis()
            try {
                runOneSession(brokerWss, brokerKey, rid, onPayload)
                // only reset backoff if the session was alive
                // long enough to count as "stable" — a broker that
                // closes the WSS within seconds of OPEN gets the
                // exponential backoff treatment, same as a network
                // failure. Without this guard, a misbehaving public
                // broker (or our own connection getting rate-limited)
                // produces a tight 1 s reconnect loop, which the
                // public broker may then escalate to a full ban.
                val durationMs = System.currentTimeMillis() - sessionStart
                Log.i("wgrtc-listener",
                    "session ended after ${durationMs}ms; backoff=${backoffMs}ms")
                if (durationMs >= STABLE_SESSION_MS) {
                    backoffMs = INITIAL_BACKOFF_MS
                }
            } catch (t: Throwable) {
                Log.w("wgrtc-listener",
                    "session threw after ${System.currentTimeMillis() - sessionStart}ms: " +
                    "${t.javaClass.simpleName}: ${t.message}; backoff=${backoffMs}ms")
            }
            // Even on a clean close we want to reconnect (long-lived
            // listener semantics). Wait, then try again. Cancellation
            // propagates through delay().
            delay(backoffMs)
            backoffMs = (backoffMs * 2).coerceAtMost(MAX_BACKOFF_MS)
        }
        Log.i("wgrtc-listener", "reconnect loop exited (rid=...${rid.takeLast(8)})")
    }

    private suspend fun runOneSession(
        brokerWss: String, brokerKey: String, rid: String,
        onPayload: (JsonElement) -> Unit,
    ) = kotlinx.coroutines.suspendCancellableCoroutine<Unit> { cont ->
        val nonce = ByteArray(8).also { SecureRandom().nextBytes(it) }
            .joinToString("") { String.format("%02x", it) }
        val sep = if ('?' in brokerWss) "&" else "?"
        val url = "$brokerWss${sep}key=$brokerKey&id=$rid&token=$nonce&version=1.5.2"
        val request = Request.Builder().url(url).build()
        // New session: clear any stale OPEN state from the previous
        // attempt before the socket connects.
        _sessionOpen.value = false

        val sessionT0 = System.currentTimeMillis()
        Log.i("wgrtc-listener", "opening WSS to $url")
        val socket = httpClient.newWebSocket(request, object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: Response) {
                Log.i("wgrtc-listener",
                    "WSS onOpen after ${System.currentTimeMillis() - sessionT0}ms " +
                    "(HTTP ${response.code}); waiting for broker OPEN frame")
            }

            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                Log.w("wgrtc-listener",
                    "WSS onFailure after ${System.currentTimeMillis() - sessionT0}ms: " +
                    "${t.javaClass.simpleName}: ${t.message} (response=${response?.code})")
                _sessionOpen.value = false
                if (cont.isActive) cont.resumeWith(Result.failure(t))
            }

            override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                Log.i("wgrtc-listener",
                    "WSS onClosed after ${System.currentTimeMillis() - sessionT0}ms: " +
                    "code=$code reason=$reason")
                _sessionOpen.value = false
                if (cont.isActive) cont.resume(Unit) {}
            }

            override fun onMessage(webSocket: WebSocket, text: String) {
                val msg = try { Json.parseToJsonElement(text) }
                          catch (_: Exception) { return }
                val type = ((msg as? JsonObject)?.get("type") as? JsonPrimitive)?.content
                if (type == "OPEN" && !_sessionOpen.value) {
                    _sessionOpen.value = true
                    Log.i("wgrtc-listener",
                        "broker OPEN at ${System.currentTimeMillis() - sessionT0}ms; " +
                        "session live")
                    // Heartbeat is fire-and-forget; if the socket
                    // closes the loop's send() returns false and we
                    // exit on the next iteration.
                    scope?.launch(Dispatchers.IO) {
                        while (webSocket === ws && kotlinx.coroutines.currentCoroutineContext()[Job]?.isActive != false) {
                            delay(HEARTBEAT_MS)
                            if (!webSocket.send("""{"type":"HEARTBEAT"}""")) break
                        }
                    }
                    return
                }
                if (!_sessionOpen.value) return
                onPayload(msg)
            }

        })
        ws = socket
        cont.invokeOnCancellation {
            // graceful close, not cancel(). When [stop] runs it
            // calls socket.close() (which flushes the outbound queue) and
            // then cancels the parent scope; that scope cancellation
            // propagates here. Using cancel() would race the queue
            // drain and drop any frame [sendThrough] had just enqueued —
            // exactly the SAS_CONFIRM-loss bug we're fixing. close() is
            // a no-op when the socket is already closing, so back-to-back
            // close + invokeOnCancellation is safe.
            try { socket.close(1000, "cancelled") } catch (_: Throwable) {}
            ws = null
        }
    }

    companion object {
        /** Broker drops idle clients after ~30 s; mirror daemon's 5 s. */
        const val HEARTBEAT_MS = 5_000L
        const val INITIAL_BACKOFF_MS = 1_000L
        const val MAX_BACKOFF_MS = 60_000L
        /** A session shorter than this is treated as a failure for
         * reconnect-backoff purposes. Picked so a normal
         * HEARTBEAT-driven keepalive roundtrip qualifies as
         * "stable" but a broker quick-close doesn't. */
        const val STABLE_SESSION_MS = 10_000L
    }
}
