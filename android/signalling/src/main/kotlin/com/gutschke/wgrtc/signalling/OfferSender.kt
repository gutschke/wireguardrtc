package com.gutschke.wgrtc.signalling

import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonObject
import java.security.SecureRandom
import java.util.Base64

/**
 * Single-method seam letting [com.gutschke.wgrtc.data.ListenerHub]
 * substitute a fake in unit tests without hooking the websocket.
 *
 * The wake's transport (which broker session carries the OFFER) is
 * supplied by the caller as [sendVia]. The sender just builds and
 * encrypts the envelope.
 */
interface SignalWakeSender {
    suspend fun sendWake(
        sendVia: suspend (envelope: String) -> Boolean,
        sigboxKey: ByteArray,
        dstRoutingId: String,
    ): Boolean
}

/**
 * One-shot sender for the `metadata.kind = "signal_wake"` envelope —
 * the client-initiated wake described in
 * ``.
 *
 * The wake carries an empty `candidates` list (the client doesn't
 * claim its own endpoint — that's the entire point of the
 * "signal_wake" discriminator: the daemon's responsive OFFER is what
 * we actually want).
 *
 * **Transport**: [sendVia] — typically [OfferListener.sendThrough] —
 * delivers the envelope through the long-lived listener WSS that's
 * already registered under our `routing_id(my_pub, salt)`. Going
 * through the listener's session is load-bearing: PeerJS forwards the
 * OFFER tagged with the originating session's broker id, and the
 * daemon's `_handle_signaling` dispatches by
 * `src_id == routing_id(peer_pub, salt)` — only the listener's id
 * matches. An earlier design opened a fresh WSS per wake under a
 * random id; the broker forwarded fine but the daemon silently
 * dropped the wake because no peer matched the random `src`.
 *
 * Higher layers (the [com.gutschke.wgrtc.data.ListenerHub]) own the
 * triggering policy: typically on Connect-while-DOWN, on app
 * foreground (debounced), and after a network change.
 */
class OfferSender : SignalWakeSender {

    /**
     * Build a `signal_wake` envelope for [dstRoutingId], encrypt the
     * payload with [sigboxKey], and dispatch via [sendVia]. Returns
     * whatever [sendVia] returned — typically true if the listener's
     * socket queued the frame, false if the listener wasn't OPEN or
     * the queue refused. Failure is non-fatal — the worst case is
     * the daemon doesn't receive our wake and the user waits up to
     * the daemon's poll cycle for a fresh inbound OFFER instead.
     */
    override suspend fun sendWake(
        sendVia: suspend (String) -> Boolean,
        sigboxKey: ByteArray,
        dstRoutingId: String,
    ): Boolean {
        val now = System.currentTimeMillis() / 1000
        val plain = """{"v":$PROTOCOL_VERSION,"ts":$now,"candidates":[]}"""
        val ct = secretboxEncrypt(plain.toByteArray(Charsets.UTF_8), sigboxKey)
        val blob = Base64.getEncoder().encodeToString(ct)

        val cid = "dc_" + ByteArray(6).also { SecureRandom().nextBytes(it) }
            .joinToString("") { String.format("%02x", it) }
        val envelope = buildJsonObject {
            put("type", "OFFER")
            put("dst", dstRoutingId)
            putJsonObject("payload") {
                put("type", "data")
                put("connectionId", cid); put("label", cid)
                put("reliable", false); put("serialization", "binary")
                putJsonObject("sdp") {
                    put("sdp", buildPeerJsSdp()); put("type", "offer")
                }
                putJsonObject("metadata") {
                    put("v", PROTOCOL_VERSION)
                    put("kind", "signal_wake")
                    put("blob", blob)
                }
            }
        }.toString()

        Log.i("wgrtc-wake",
            "sending signal_wake envelope via listener WSS " +
            "(dst=...${dstRoutingId.takeLast(8)}, bytes=${envelope.length})")
        val ok = sendVia(envelope)
        if (!ok) {
            Log.w("wgrtc-wake",
                "sendVia returned false (listener not OPEN, socket closing, " +
                "or queue refused frame)")
        }
        return ok
    }
}
