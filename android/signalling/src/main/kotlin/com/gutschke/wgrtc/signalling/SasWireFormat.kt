package com.gutschke.wgrtc.signalling

import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonObject
import java.security.MessageDigest
import java.util.Base64

/**
 * Wormhole-code (SPAKE2 + SAS) wire format.
 *
 * This is the *plaintext* signalling format that travels over the
 * broker WSS during wormhole-code enrolment. Unlike the
 * existing [buildEnrollEnvelope] flow (which encrypts via a
 * pre-shared sigbox key), the SAS flow has no shared secret yet —
 * the SPAKE2 messages themselves are the key-establishment. SPAKE2
 * is designed so the messages don't leak the password; an attacker
 * who relays one half can complete PAKE on each side independently
 * but ends up with *different* shared keys, which the human SAS-
 * confirmation step catches.
 *
 * Three message kinds, all carried inside the existing OFFER
 * envelope shape so they survive the public PeerJS broker's
 * payload-shape filter:
 *
 * 1. [SAS_STEP_1] — initiator → responder, contains
 * [Spake2.start] output (32-byte Ristretto255 point).
 * 2. [SAS_STEP_2] — responder → initiator, contains
 * [Spake2.start] output (their 32-byte point).
 * 3. [SAS_CONFIRM] — bidirectional after human SAS-display
 * confirmation, contains a 16-byte keyed-blake2b MAC over a
 * role-specific tag. Each side sends its own role's MAC and
 * verifies the peer's role MAC; mismatch ⇒ key disagreement
 * ⇒ abort. Constant-time compare via [MessageDigest.isEqual].
 *
 * Routing-id derivation: in the wormhole flow, neither side
 * knows the other's WG pubkey ahead of time. Both derive a routing
 * id from the *wormhole code* alone, with role-specific labels:
 * [sasRoutingIdInitiator] / [sasRoutingIdResponder]. Dropping
 * either label would let the broker correlate by code-hash; with
 * them, an observer needs to enumerate the same code (low entropy
 * by design — see [Spake2Sas.deriveSas] threat-model notes) before
 * they can subscribe to the same routing id. In practice that's
 * the same attack surface as guessing the code and joining the
 * SPAKE2; SAS catches it on the human confirmation step.
 *
 * Wire-format compatibility: the strings below are protocol
 * commitments — bumping any of them is a protocol break that
 * requires raising [PROTOCOL_VERSION]. All MUST stay synchronised
 * with the daemon side (CLAUDE.md / wire-format invariants).
 */
const val SAS_STEP_1 = "sas_step_1"
const val SAS_STEP_2 = "sas_step_2"
const val SAS_CONFIRM = "sas_confirm"

/** Role identifier for [buildSasConfirmMac] / [verifySasConfirmMac].
 * Initiator is the side that ran [SAS_STEP_1]; responder ran
 * [SAS_STEP_2]. Each side computes its own role's MAC, sends it,
 * and verifies the peer's role-MAC. */
enum class SasConfirmRole { INITIATOR, RESPONDER }

private val LABEL_SAS_ROUTING_INIT: ByteArray =
    "wgrtc/sas/routing-init-2026".toByteArray(Charsets.UTF_8)
private val LABEL_SAS_ROUTING_RESP: ByteArray =
    "wgrtc/sas/routing-resp-2026".toByteArray(Charsets.UTF_8)
private val LABEL_SAS_CONFIRM_INIT: ByteArray =
    "wgrtc/sas/confirm-init-2026".toByteArray(Charsets.UTF_8)
private val LABEL_SAS_CONFIRM_RESP: ByteArray =
    "wgrtc/sas/confirm-resp-2026".toByteArray(Charsets.UTF_8)

/** Length of the SPAKE2 wire message (one Ristretto255 point). */
const val SAS_PAKE_MSG_LEN: Int = 32

/** Length of the [SAS_CONFIRM] MAC. 16 bytes = 128-bit forgery
 * resistance — adequate against a non-rate-limited online MAC
 * forgery attempt; the broker rate-limits to milliseconds-per-
 * attempt, far below any practical 2^128 budget. */
const val SAS_CONFIRM_MAC_LEN: Int = 16

private val B64_STD = Base64.getEncoder()
private val B64_DEC = Base64.getDecoder()
private val B64_URL = Base64.getUrlEncoder().withoutPadding()

/**
 * Routing id (broker-side subscription key) for the *initiator*'s
 * inbox. Both sides know the same wormhole code; each subscribes
 * to its own role's id. URL-safe-base64 no padding to match the
 * existing [routingId] format that broker IDs use over WSS.
 *
 * @param code the shared wormhole-code bytes (UTF-8 of the typed
 * string after normalisation, or whatever the UI chose).
 */
fun sasRoutingIdInitiator(code: ByteArray): String =
    B64_URL.encodeToString(blake2b32(code, LABEL_SAS_ROUTING_INIT))

/** Routing id for the *responder*'s inbox. See [sasRoutingIdInitiator]. */
fun sasRoutingIdResponder(code: ByteArray): String =
    B64_URL.encodeToString(blake2b32(code, LABEL_SAS_ROUTING_RESP))

// ─────────────────────────────────────────────────────────────────
// Step-1 / Step-2 wire format (carries SPAKE2 messages).

/** Wrap [pakeMsg] in an OFFER envelope tagged [SAS_STEP_1]. */
fun buildSasStep1Envelope(dstRoutingId: String, pakeMsg: ByteArray): JsonElement {
    require(pakeMsg.size == SAS_PAKE_MSG_LEN) {
        "pakeMsg must be $SAS_PAKE_MSG_LEN bytes (got ${pakeMsg.size})"
    }
    return buildSasEnvelope(dstRoutingId, kind = SAS_STEP_1) {
        put("pake_msg", B64_STD.encodeToString(pakeMsg))
    }
}

/** Wrap [pakeMsg] in an OFFER envelope tagged [SAS_STEP_2]. */
fun buildSasStep2Envelope(dstRoutingId: String, pakeMsg: ByteArray): JsonElement {
    require(pakeMsg.size == SAS_PAKE_MSG_LEN) {
        "pakeMsg must be $SAS_PAKE_MSG_LEN bytes (got ${pakeMsg.size})"
    }
    return buildSasEnvelope(dstRoutingId, kind = SAS_STEP_2) {
        put("pake_msg", B64_STD.encodeToString(pakeMsg))
    }
}

/** Wrap [confirmMac] in an OFFER envelope tagged [SAS_CONFIRM].
 * Optional [encryptedInfo]: a secretbox-with-K ciphertext carrying
 * [JoinerEnrolInfo] (joiner→host) or [HostEnrolInfo] (host→joiner);
 * see those classes' kdocs. Backward-compat: omit [encryptedInfo]
 * for the legacy mac-only behaviour. */
fun buildSasConfirmEnvelope(
    dstRoutingId: String,
    confirmMac: ByteArray,
    encryptedInfo: ByteArray? = null,
): JsonElement {
    require(confirmMac.size == SAS_CONFIRM_MAC_LEN) {
        "confirmMac must be $SAS_CONFIRM_MAC_LEN bytes (got ${confirmMac.size})"
    }
    return buildSasEnvelope(dstRoutingId, kind = SAS_CONFIRM) {
        put("mac", B64_STD.encodeToString(confirmMac))
        if (encryptedInfo != null) {
            put("info", B64_STD.encodeToString(encryptedInfo))
        }
    }
}

/**
 * Inbound [SAS_STEP_1] / [SAS_STEP_2] decoded. `src` is the
 * broker-set sender id; the receiver should sanity-check it against
 * the expected routing id derived from the same wormhole code.
 */
data class InboundSasStep(
    val src: String,
    val pakeMsg: ByteArray,
) {
    override fun equals(other: Any?): Boolean =
        other is InboundSasStep && src == other.src && pakeMsg.contentEquals(other.pakeMsg)
    override fun hashCode(): Int = 31 * src.hashCode() + pakeMsg.contentHashCode()
}

/** Inbound [SAS_CONFIRM] decoded. [encryptedInfo] is the optional
 * secretbox blob — null if the sender omitted the field (legacy
 * mac-only confirm). */
data class InboundSasConfirm(
    val src: String,
    val mac: ByteArray,
    val encryptedInfo: ByteArray? = null,
) {
    override fun equals(other: Any?): Boolean =
        other is InboundSasConfirm && src == other.src &&
            mac.contentEquals(other.mac) &&
            ((encryptedInfo == null && other.encryptedInfo == null) ||
             (encryptedInfo != null && other.encryptedInfo != null &&
              encryptedInfo.contentEquals(other.encryptedInfo)))
    override fun hashCode(): Int {
        var h = 31 * src.hashCode() + mac.contentHashCode()
        if (encryptedInfo != null) h = 31 * h + encryptedInfo.contentHashCode()
        return h
    }
}

/** Pull a [SAS_STEP_1] envelope's pake_msg out, or null if the
 * message isn't one. */
fun extractSasStep1(message: JsonElement): InboundSasStep? =
    extractSasStep(message, expectedKind = SAS_STEP_1)

/** Pull a [SAS_STEP_2] envelope's pake_msg out, or null. */
fun extractSasStep2(message: JsonElement): InboundSasStep? =
    extractSasStep(message, expectedKind = SAS_STEP_2)

/** Pull a [SAS_CONFIRM] envelope's mac (and optional encrypted info)
 * out, or null on any structural mismatch. */
fun extractSasConfirm(message: JsonElement): InboundSasConfirm? {
    val (src, md) = extractSasMetadata(message, expectedKind = SAS_CONFIRM) ?: return null
    val macB64 = (md["mac"] as? JsonPrimitive)?.contentOrNullStrict ?: return null
    val mac = try { B64_DEC.decode(macB64) } catch (_: Exception) { return null }
    if (mac.size != SAS_CONFIRM_MAC_LEN) return null
    val infoB64 = (md["info"] as? JsonPrimitive)?.contentOrNullStrict
    val info = if (infoB64 == null) null
        else try { B64_DEC.decode(infoB64) } catch (_: Exception) { return null }
    return InboundSasConfirm(src, mac, info)
}

// ─────────────────────────────────────────────────────────────────
// Confirm-MAC: keyed-blake2b over a role-specific 16-byte tag.

/**
 * Compute the 16-byte confirm-MAC for [role], keyed on the SPAKE2-
 * derived [sasKey] (the 32-byte output of [Spake2.finish]). Each
 * side sends its own role's MAC; the peer recomputes the *opposite*
 * role's MAC and compares.
 *
 * The role-specific label gives explicit cross-role separation:
 * even if a buggy implementation accidentally treats both sides as
 * the same role, neither MAC validates against the other.
 */
fun buildSasConfirmMac(role: SasConfirmRole, sasKey: ByteArray): ByteArray {
    require(sasKey.size >= 16) {
        "sasKey too short (got ${sasKey.size}, need ≥ 16)"
    }
    val label = when (role) {
        SasConfirmRole.INITIATOR -> LABEL_SAS_CONFIRM_INIT
        SasConfirmRole.RESPONDER -> LABEL_SAS_CONFIRM_RESP
    }
    // 32-byte output truncated to 16 — equivalent to a native 16-byte
    // blake2b in security terms, and avoids needing a separate
    // blake2bN helper just for one call site.
    val full = blake2b32(label, sasKey.copyOfRange(0, 32.coerceAtMost(sasKey.size)))
    return full.copyOfRange(0, SAS_CONFIRM_MAC_LEN)
}

/**
 * Verify a peer's confirm-MAC. [peerRole] is the *peer's* role
 * (i.e. the opposite of the local side). Constant-time compare
 * via [MessageDigest.isEqual].
 */
fun verifySasConfirmMac(
    peerRole: SasConfirmRole,
    sasKey: ByteArray,
    receivedMac: ByteArray,
): Boolean {
    if (receivedMac.size != SAS_CONFIRM_MAC_LEN) return false
    val expected = buildSasConfirmMac(peerRole, sasKey)
    return MessageDigest.isEqual(expected, receivedMac)
}

// ─────────────────────────────────────────────────────────────────
// Internal envelope helpers.

private fun buildSasEnvelope(
    dstRoutingId: String,
    kind: String,
    fillMetadata: kotlinx.serialization.json.JsonObjectBuilder.() -> Unit,
): JsonElement {
    val connId = "dc_" + secretsTokenHexLocal(6)
    return buildJsonObject {
        put("type", "OFFER")
        put("dst", dstRoutingId)
        putJsonObject("payload") {
            putJsonObject("sdp") {
                put("sdp", buildPeerJsSdp())
                put("type", "offer")
            }
            put("type", "data")
            put("connectionId", connId)
            put("label", connId)
            put("reliable", false)
            put("serialization", "binary")
            putJsonObject("metadata") {
                put("v", PROTOCOL_VERSION)
                put("kind", kind)
                fillMetadata()
            }
        }
    }
}

private fun extractSasStep(
    message: JsonElement,
    expectedKind: String,
): InboundSasStep? {
    val (src, md) = extractSasMetadata(message, expectedKind) ?: return null
    val pakeMsgB64 = (md["pake_msg"] as? JsonPrimitive)?.contentOrNullStrict ?: return null
    val pakeMsg = try { B64_DEC.decode(pakeMsgB64) } catch (_: Exception) { return null }
    if (pakeMsg.size != SAS_PAKE_MSG_LEN) return null
    return InboundSasStep(src, pakeMsg)
}

/** Common parser: returns (src, metadata) for any SAS envelope of
 * the expected kind, or null on any structural mismatch. */
private fun extractSasMetadata(
    message: JsonElement,
    expectedKind: String,
): Pair<String, JsonObject>? {
    if (message !is JsonObject) return null
    val type = (message["type"] as? JsonPrimitive)?.contentOrNullStrict
    if (type != "OFFER") return null
    val src = (message["src"] as? JsonPrimitive)?.contentOrNullStrict ?: return null
    val payload = message["payload"] as? JsonObject ?: return null
    val md = payload["metadata"] as? JsonObject ?: return null
    val v = (md["v"] as? JsonPrimitive)?.contentOrNullStrict
    if (v != PROTOCOL_VERSION.toString()) return null
    val kind = (md["kind"] as? JsonPrimitive)?.contentOrNullStrict
    if (kind != expectedKind) return null
    return src to md
}

private val JsonPrimitive.contentOrNullStrict: String?
    get() = if (isString) content else content

private fun secretsTokenHexLocal(nbytes: Int): String {
    val rng = java.security.SecureRandom()
    val buf = ByteArray(nbytes)
    rng.nextBytes(buf)
    return buf.joinToString("") { "%02x".format(it) }
}
