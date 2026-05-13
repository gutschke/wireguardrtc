package com.gutschke.wgrtc.signalling

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonObject
import java.security.SecureRandom

/**
 * Wire-format constants and helpers shared across signalling
 * (OFFER) and enrollment (ENROLL/ENROLL_OK/ENROLL_ERR). Both flows
 * ride inside the same WebRTC OFFER envelope so they survive the
 * public PeerJS broker's payload-shape filter (CLAUDE.md invariant 3
 * in the parent project).
 */
const val PROTOCOL_VERSION = 1

// `encodeDefaults = true` is critical: the daemon rejects ENROLL blobs
// that don't carry an explicit `v` (PROTOCOL_VERSION) field. Default
// kotlinx.serialization behavior drops fields whose value equals
// their default, which would silently break interop.
internal val JSON = Json {
    ignoreUnknownKeys = true
    encodeDefaults = true
}

private val HEX = "0123456789abcdef"
private fun secretsTokenHex(nbytes: Int): String {
    val out = StringBuilder(nbytes * 2)
    val buf = ByteArray(nbytes)
    SecureRandom().nextBytes(buf)
    for (b in buf) {
        out.append(HEX[(b.toInt() ushr 4) and 0xf])
        out.append(HEX[b.toInt() and 0xf])
    }
    return out.toString()
}

/**
 * Generate a syntactically-plausible WebRTC datachannel SDP body.
 * Required by the public PeerJS broker, which drops messages whose
 * SDP doesn't look like a real datachannel offer. Fields are random
 * per call (matches what the daemon does in `build_peerjs_sdp`).
 */
fun buildPeerJsSdp(): String {
    val sid = (java.security.SecureRandom().nextLong() and Long.MAX_VALUE).toString()
    val ufrag = secretsTokenHex(2)
    val pwd = secretsTokenHex(12)
    val fp = ByteArray(32).also { SecureRandom().nextBytes(it) }
        .joinToString(":") { String.format("%02X", it) }
    return buildString {
        append("v=0\r\n")
        append("o=- $sid 2 IN IP4 127.0.0.1\r\n")
        append("s=-\r\n")
        append("t=0 0\r\n")
        append("a=group:BUNDLE 0\r\n")
        append("a=extmap-allow-mixed\r\n")
        append("a=msid-semantic: WMS\r\n")
        append("m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n")
        append("c=IN IP4 0.0.0.0\r\n")
        append("a=ice-ufrag:$ufrag\r\n")
        append("a=ice-pwd:$pwd\r\n")
        append("a=ice-options:trickle\r\n")
        append("a=fingerprint:sha-256 $fp\r\n")
        append("a=setup:actpass\r\n")
        append("a=mid:0\r\n")
        append("a=sctp-port:5000\r\n")
        append("a=max-message-size:262144\r\n")
    }
}

/**
 * Wrap an enrollment ciphertext in the WebRTC OFFER envelope the
 * broker expects. `metadata.kind = "enroll"` discriminates against
 * the existing signalling-OFFER format which has no `kind` field.
 */
fun buildEnrollEnvelope(
    dstRoutingId: String,
    clientPubBase64: String,
    blobBase64: String,
): JsonElement {
    val connId = "dc_" + secretsTokenHex(6)
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
                put("kind", "enroll")
                put("client_pub", clientPubBase64)
                put("blob", blobBase64)
            }
        }
    }
}

/**
 * Inbound `metadata.kind = "enroll"` envelope, decoded into the
 * three load-bearing fields a host-mode () ENROLL handler
 * needs to validate the request.
 *
 * - [src] is the broker-set sender id (the server uses this to
 * sanity-check `src == routing_id(client_pub, salt)`).
 * - [clientPubB64] is the client's WireGuard public key, copied
 * out of the unencrypted metadata so the server can derive the
 * per-(client, token) sigbox key without first knowing the
 * client.
 * - [blobB64] is the encrypted ENROLL plaintext.
 */
data class InboundEnrollEnvelope(
    val src: String,
    val clientPubB64: String,
    val blobB64: String,
)

/**
 * Pull the inbound-ENROLL fields out of a broker-forwarded OFFER.
 * Returns null on any structural mismatch (wrong type, missing
 * `kind=enroll`, malformed `client_pub`, etc.).
 */
fun extractInboundEnroll(message: JsonElement): InboundEnrollEnvelope? {
    if (message !is JsonObject) return null
    val type = (message["type"] as? JsonPrimitive)?.contentOrNull
    if (type != "OFFER") return null
    val src = (message["src"] as? JsonPrimitive)?.contentOrNull ?: return null
    val payload = message["payload"] as? JsonObject ?: return null
    val md = payload["metadata"] as? JsonObject ?: return null
    val v = (md["v"] as? JsonPrimitive)?.contentOrNull
    if (v != PROTOCOL_VERSION.toString()) return null
    val kind = (md["kind"] as? JsonPrimitive)?.contentOrNull
    if (kind != "enroll") return null
    val clientPub = (md["client_pub"] as? JsonPrimitive)?.contentOrNull ?: return null
    val blob = (md["blob"] as? JsonPrimitive)?.contentOrNull ?: return null
    return InboundEnrollEnvelope(src, clientPub, blob)
}

/**
 * Wrap an enrollment-response ciphertext in the same OFFER envelope
 * shape used by [buildEnrollEnvelope], with `metadata.kind` set to
 * either `"enroll_ok"` or `"enroll_err"` and `metadata.server_pub`
 * carrying the host's WG public key. Mirror of the daemon's
 * `build_enroll_envelope`.
 */
fun buildEnrollResponseEnvelope(
    dstRoutingId: String,
    kind: String,
    serverPubBase64: String,
    blobBase64: String,
): JsonElement {
    require(kind == "enroll_ok" || kind == "enroll_err") {
        "kind must be enroll_ok or enroll_err, got $kind"
    }
    val connId = "dc_" + secretsTokenHex(6)
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
                put("server_pub", serverPubBase64)
                put("blob", blobBase64)
            }
        }
    }
}

/**
 * Pull (kind, blob_b64) out of an inbound enrollment-response
 * envelope, or null if it isn't one.
 */
fun extractEnrollResponse(message: JsonElement): Pair<String, String>? {
    if (message !is JsonObject) return null
    val type = (message["type"] as? JsonPrimitive)?.contentOrNull
    if (type != "OFFER") return null
    val payload = message["payload"] as? JsonObject ?: return null
    val md = payload["metadata"] as? JsonObject ?: return null
    val v = (md["v"] as? JsonPrimitive)?.contentOrNull
    if (v != PROTOCOL_VERSION.toString()) return null
    val kind = (md["kind"] as? JsonPrimitive)?.contentOrNull ?: return null
    if (kind != "enroll_ok" && kind != "enroll_err") return null
    val blob = (md["blob"] as? JsonPrimitive)?.contentOrNull ?: return null
    return kind to blob
}

/**
 * Pull the encrypted blob out of an inbound *signalling* OFFER, or
 * null if the message is something else. Mirrors the daemon's
 * [extract_envelope] behavior: signalling OFFERs are discriminated
 * from enrollment OFFERs by the absence of `metadata.kind` (or by
 * `metadata.kind` being something other than the enrollment kinds).
 *
 * Returns the base64-encoded ciphertext blob; the caller decrypts it
 * with the sigbox key.
 */
fun extractSignallingOffer(message: JsonElement): String? {
    if (message !is JsonObject) return null
    val type = (message["type"] as? JsonPrimitive)?.contentOrNull
    if (type != "OFFER") return null
    val payload = message["payload"] as? JsonObject ?: return null
    val md = payload["metadata"] as? JsonObject ?: return null
    val v = (md["v"] as? JsonPrimitive)?.contentOrNull
    if (v != PROTOCOL_VERSION.toString()) return null
    val kind = (md["kind"] as? JsonPrimitive)?.contentOrNull
    // Signalling OFFER iff `kind` is absent. The daemon also ignores
    // unknown kinds — match that behavior rather than bail.
    if (kind != null && kind != "") return null
    return (md["blob"] as? JsonPrimitive)?.contentOrNull
}

/**
 * Decrypt + validate an endpoint payload from a signalling OFFER.
 * Returns null on any error (malformed base64, bad MAC, wrong
 * version, stale timestamp, empty candidates list, all-invalid
 * candidates, junk types) — failure modes are silent so an attacker
 * can't probe by measuring response shapes.
 *
 * Mirrors the daemon's [decrypt_envelope] exactly. Wire format has
 * a `candidates: [{ip, port, kind}, ...]` array; we return the FIRST
 * entry that passes validation as an [EndpointUpdate]. Receivers
 * that want the full candidate list use [decryptEndpointCandidates].
 */
fun decryptEndpointBlob(
    sigboxKey: ByteArray,
    blobBase64: String,
    nowEpochSeconds: Long = System.currentTimeMillis() / 1000,
    freshnessWindowSeconds: Long = PROTOCOL_FRESHNESS_WINDOW_SECONDS,
    rejectIfInside: List<String> = emptyList(),
): EndpointUpdate? {
    val all = decryptEndpointCandidates(
        sigboxKey, blobBase64, nowEpochSeconds, freshnessWindowSeconds,
        rejectIfInside,
    ) ?: return null
    return all.firstOrNull()
}

/**
 * Like [decryptEndpointBlob] but returns the full ordered list of
 * candidates the sender claimed. An empty list (or all-invalid)
 * yields null. Order is preserved — the sender ranks by preference
 * (e.g. host-mode-on-hotspot fills [LAN, STUN] in that order).
 *
 * [rejectIfInside] is the receiver's bootstrap-deadlock guard: a CIDR
 * list (typically from `parseAllowedIps(tunnel.configText)`). Any
 * candidate whose IP falls inside is dropped — using such an IP as
 * an Endpoint would make the kernel route handshake packets back
 * into the tunnel that needs the handshake to come up. See
 * `` §"Receiver
 * rules / Bootstrap deadlock".
 */
fun decryptEndpointCandidates(
    sigboxKey: ByteArray,
    blobBase64: String,
    nowEpochSeconds: Long = System.currentTimeMillis() / 1000,
    freshnessWindowSeconds: Long = PROTOCOL_FRESHNESS_WINDOW_SECONDS,
    rejectIfInside: List<String> = emptyList(),
): List<EndpointUpdate>? {
    if (blobBase64.length > MAX_SIGBOX_CIPHERTEXT_B64) return null
    val ct = try { java.util.Base64.getDecoder().decode(blobBase64) }
             catch (_: Exception) { return null }
    val plain = secretboxDecrypt(ct, sigboxKey) ?: return null
    if (plain.size > MAX_SIGBOX_PLAINTEXT) return null
    val obj = try {
        Json.parseToJsonElement(plain.toString(Charsets.UTF_8)) as? JsonObject
    } catch (_: Exception) { return null } ?: return null
    val v = (obj["v"] as? JsonPrimitive)?.content?.toIntOrNull() ?: return null
    if (v != PROTOCOL_VERSION) return null
    val ts = (obj["ts"] as? JsonPrimitive)?.content?.toLongOrNull() ?: return null
    if (kotlin.math.abs(nowEpochSeconds - ts) > freshnessWindowSeconds) return null
    val candidates = obj["candidates"]
        as? kotlinx.serialization.json.JsonArray ?: return null
    val out = mutableListOf<EndpointUpdate>()
    for (entry in candidates) {
        val cobj = entry as? JsonObject ?: continue
        val ip = (cobj["ip"] as? JsonPrimitive)?.contentOrNull ?: continue
        val port = (cobj["port"] as? JsonPrimitive)?.content?.toIntOrNull()
            ?: continue
        if (!isValidPublicEndpoint(ip, port)) continue
        if (isInAnyCidr(ip, rejectIfInside)) continue
        out.add(EndpointUpdate(ip = ip, port = port, ts = ts))
    }
    return if (out.isEmpty()) null else out
}

/** Mirror of the daemon's `is_valid_public_endpoint` — reject loopback,
 * link-local, multicast, unspecified, reserved, and weirdly-low ports.
 * RFC 1918 private addresses ARE accepted (LAN candidate kind).
 *
 * Resolution must NOT consult DNS — a malicious sender could otherwise
 * starve the receiver by burying expensive lookups in the candidate
 * list. We require [ip] to be a literal address (numeric IPv4 dotted
 * quad or square-bracketed IPv6) and reject anything that isn't. */
private fun isValidPublicEndpoint(ip: String, port: Int): Boolean {
    if (port !in 1..65535) return false
    if (!IP_LITERAL.matches(ip)) return false
    val addr = try { java.net.InetAddress.getByName(ip) }
               catch (_: Exception) { return false }
    if (addr.isLoopbackAddress) return false
    if (addr.isMulticastAddress) return false
    if (addr.isLinkLocalAddress) return false
    if (addr.isAnyLocalAddress) return false // 0.0.0.0 / ::
    return true
}

// Conservative literal-IP recognizer. IPv4: four dotted decimals.
// IPv6: anything containing ":" with no DNS-shaped characters. False
// positives are filtered by the InetAddress.getByName check below;
// the regex only short-circuits the obvious "this is a hostname" case
// to avoid a DNS lookup.
private val IP_LITERAL = Regex(
    """^(\d{1,3}(\.\d{1,3}){3}|[0-9a-fA-F:]+)$"""
)

/** Wire-format constants shared with the daemon (cf. `wireguardrtc`'s
 * `MAX_SIGBOX_*` and `PROTOCOL_FRESHNESS_WINDOW`). Changing these
 * silently breaks compatibility — they're protocol commitments, not
 * implementation knobs.
 */
const val MAX_SIGBOX_PLAINTEXT = 1024
const val MAX_SIGBOX_CIPHERTEXT_B64 = 2048
const val PROTOCOL_FRESHNESS_WINDOW_SECONDS = 90L

/** Signalling OFFER decoded payload — the daemon's current
 * STUN-discovered (host, port) for its WG listener, plus the
 * timestamp the daemon emitted at. */
data class EndpointUpdate(
    val ip: String,
    val port: Int,
    val ts: Long,
)

/** kotlinx.serialization helper — content-as-string of a JsonPrimitive. */
private val JsonPrimitive.contentOrNull: String?
    get() = if (isString) content else content

/** ENROLL request plaintext. Fields chosen to match the daemon's expectations. */
@Serializable
data class EnrollRequestPlain(
    @SerialName("v") val version: Int = PROTOCOL_VERSION,
    @SerialName("ts") val timestamp: Long,
    @SerialName("token_check") val tokenCheck: String,
    @SerialName("hint") val hint: String,
    @SerialName("device") val device: String,
    @SerialName("client_caps") val clientCaps: ClientCaps = ClientCaps(),
)

@Serializable
data class ClientCaps(
    @SerialName("obfs") val obfs: List<String> = emptyList(),
    @SerialName("transport") val transport: List<String> = listOf("udp"),
)

/** One entry in the ranked endpoint candidate list the daemon ships
 * inside ENROLL_OK and inside OFFER envelopes. Mirrors the daemon's
 * `discover_local_candidates` output; ordering is rank-ascending
 * (LAN ahead of public when both apply). */
@Serializable
data class EndpointCandidate(
    @SerialName("ip") val ip: String,
    @SerialName("port") val port: Int,
    @SerialName("kind") val kind: String? = null,
)

/** ENROLL_OK plaintext (fields produced by the daemon — see PLAN §4.4.2). */
@Serializable
data class EnrollOkPlain(
    @SerialName("v") val version: Int,
    @SerialName("ts") val timestamp: Long,
    @SerialName("address") val address: String,
    @SerialName("allowed_ips") val allowedIps: String? = null,
    @SerialName("dns") val dns: String? = null,
    @SerialName("keepalive") val keepalive: Int? = null,
    @SerialName("mtu") val mtu: Int? = null,
    @SerialName("server_pubkey") val serverPubkey: String? = null,
    @SerialName("server_endpoint_hint") val serverEndpointHint: String? = null,
    @SerialName("obfs_params") val obfsParams: String? = null,
    @SerialName("name") val name: String? = null,
    /**
     * Full ranked candidate list the daemon discovered at enrollment
     * time (LAN, STUN, PublicIp, mesh). Lets the client race the
     * complete set on first connect rather than committing to the
     * single `server_endpoint_hint` — critical when the phone shares
     * a subnet with the server (hotspot / same LAN), so the connect
     * doesn't needlessly hairpin through the carrier. Optional for
     * back-compat with older daemons; null/empty means "race only the
     * server_endpoint_hint as a single candidate".
     */
    @SerialName("candidates") val candidates: List<EndpointCandidate>? = null,
)

/** ENROLL_ERR plaintext. */
@Serializable
data class EnrollErrPlain(
    @SerialName("v") val version: Int,
    @SerialName("ts") val timestamp: Long,
    @SerialName("code") val code: String,
    @SerialName("note") val note: String? = null,
    @SerialName("retry_after") val retryAfter: Int? = null,
)
