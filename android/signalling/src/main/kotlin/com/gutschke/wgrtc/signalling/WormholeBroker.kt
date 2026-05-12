package com.gutschke.wgrtc.signalling

import kotlinx.coroutines.CoroutineScope
import kotlinx.serialization.json.JsonElement

/**
 * Transport-level abstraction over the broker WSS for the
 * wormhole flow. Owns one subscription (under a routing-id derived
 * from the wormhole code) and lets the caller send signed JSON
 * envelopes through the same connection.
 *
 * The production implementation [OfferListenerWormholeTransport]
 * wraps [OfferListener.startWithRoutingId] / [OfferListener.sendThrough].
 * Tests use a fake. The interface is narrow on purpose — it's the
 * single seam between the SAS state machine and the broker.
 */
interface WormholeTransport {
    /** Open the broker subscription and begin delivering inbound
     * payloads to [onInbound]. **Suspends until the broker has
     * sent its `OPEN` frame** so the very next [send] call is
     * guaranteed not to race against the WSS handshake. Throws
     * if the session can't be opened within an implementation-
     * defined timeout. */
    suspend fun start(routingId: String, onInbound: (JsonElement) -> Unit)

    /** Publish [envelope] over the existing connection. Returns
     * false only if the session was dropped between [start] and
     * this call. */
    fun send(envelope: JsonElement): Boolean

    /** Tear down the subscription. */
    suspend fun close()
}

/**
 * Production [WormholeTransport] backed by [OfferListener].
 * Delegates lifecycle to the underlying listener (one OfferListener
 * per WormholeTransport instance — they're cheap, and the wormhole
 * flow is short-lived enough that sharing a connection across
 * sessions wouldn't pay back the complexity).
 */
class OfferListenerWormholeTransport(
    private val brokerWss: String,
    private val brokerKey: String,
    private val parentScope: CoroutineScope,
    private val listener: OfferListener = OfferListener(),
) : WormholeTransport {

    override suspend fun start(routingId: String, onInbound: (JsonElement) -> Unit) {
        listener.startWithRoutingId(
            parentScope = parentScope,
            brokerWss = brokerWss,
            brokerKey = brokerKey,
            routingId = routingId,
            onPayload = onInbound,
        )
        // startWithRoutingId only spawns the connect coroutine; we
        // need the broker's `OPEN` frame before the first send is
        // safe. Without this wait, the very next sendStep1 races
        // and is rejected with "session not OPEN" — the user-facing
        // "broker refused step-1 send" error.
        if (!listener.awaitSessionOpen(BROKER_OPEN_TIMEOUT_MS)) {
            try { listener.stop() } catch (_: Throwable) {}
            throw java.io.IOException(
                "broker session did not open within " +
                "${BROKER_OPEN_TIMEOUT_MS}ms"
            )
        }
    }

    override fun send(envelope: JsonElement): Boolean =
        listener.sendThrough(envelope.toString())

    override suspend fun close() {
        listener.stop()
    }

    private companion object {
        const val BROKER_OPEN_TIMEOUT_MS = 15_000L
    }
}

/**
 * One-side wormhole broker session. Demultiplexes inbound payloads
 * by SAS message kind ([extractSasStep1] / [extractSasStep2] /
 * [extractSasConfirm]) and exposes typed sends for each kind.
 *
 * The session is role-aware: an [SasConfirmRole.INITIATOR] subscribes
 * under [sasRoutingIdInitiator] and sends to [sasRoutingIdResponder]
 * (and vice versa). Routing-id derivation happens at construction so
 * the caller doesn't need to know about labels.
 *
 * Lifecycle:
 * 1. [start] → opens the subscription. [onInbound] fires for
 * every well-formed inbound SAS payload (malformed messages are
 * silently dropped — the broker WSS can deliver junk and we
 * don't want spurious state-machine transitions).
 * 2. [sendStep1] / [sendStep2] / [sendConfirm] → publish to the
 * *peer's* routing id.
 * 3. [close] → stop the subscription. Idempotent.
 */
class WormholeBrokerSession(
    val role: SasConfirmRole,
    codeBytes: ByteArray,
    private val transport: WormholeTransport,
) {
    val ourRoutingId: String = when (role) {
        SasConfirmRole.INITIATOR -> sasRoutingIdInitiator(codeBytes)
        SasConfirmRole.RESPONDER -> sasRoutingIdResponder(codeBytes)
    }

    val peerRoutingId: String = when (role) {
        SasConfirmRole.INITIATOR -> sasRoutingIdResponder(codeBytes)
        SasConfirmRole.RESPONDER -> sasRoutingIdInitiator(codeBytes)
    }

    @Volatile private var started = false
    @Volatile private var closed = false

    suspend fun start(onInbound: (SasInbound) -> Unit) {
        check(!started) { "already started" }
        check(!closed) { "session is closed" }
        started = true
        transport.start(ourRoutingId) { msg ->
            val event = decodeSasInbound(msg) ?: return@start
            onInbound(event)
        }
    }

    fun sendStep1(pakeMsg: ByteArray): Boolean =
        transport.send(buildSasStep1Envelope(peerRoutingId, pakeMsg))

    fun sendStep2(pakeMsg: ByteArray): Boolean =
        transport.send(buildSasStep2Envelope(peerRoutingId, pakeMsg))

    fun sendConfirm(mac: ByteArray): Boolean =
        transport.send(buildSasConfirmEnvelope(peerRoutingId, mac))

    /** Same as [sendConfirm] but includes the encrypted [info] blob
     * the enrolment-payload extension requires. Falls back
     * cleanly: an older receiver that only checks `mac` ignores
     * the extra field. */
    fun sendConfirmWithInfo(mac: ByteArray, info: ByteArray): Boolean =
        transport.send(buildSasConfirmEnvelope(peerRoutingId, mac, encryptedInfo = info))

    suspend fun close() {
        if (closed) return
        closed = true
        try { transport.close() } catch (_: Throwable) {}
    }
}

/** Typed inbound SAS event after demuxing a broker payload. */
sealed class SasInbound {
    data class Step1(val parsed: InboundSasStep) : SasInbound()
    data class Step2(val parsed: InboundSasStep) : SasInbound()
    data class Confirm(val parsed: InboundSasConfirm) : SasInbound()
}

/** Pure decode helper — returns null for any non-SAS payload (so a
 * caller can chain other dispatchers if it wanted, though wormhole
 * sessions only see SAS traffic in practice). */
internal fun decodeSasInbound(message: JsonElement): SasInbound? {
    extractSasStep1(message)?.let { return SasInbound.Step1(it) }
    extractSasStep2(message)?.let { return SasInbound.Step2(it) }
    extractSasConfirm(message)?.let { return SasInbound.Confirm(it) }
    return null
}
