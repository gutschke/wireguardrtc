package com.gutschke.wgrtc.signalling

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.util.Base64

/**
 * Encrypted-with-K payload schemas for the wormhole flow.
 *
 * Both sides exchange one of these inside the optional `info` field
 * of [SAS_CONFIRM] envelopes, encrypted with the SPAKE2-derived
 * shared key via NaCl secretbox. The shared key is the same K
 * already used for [buildSasConfirmMac] — using one key for both
 * the MAC and the secretbox is fine because the MAC's role-specific
 * label and the secretbox's nonce-prefix mode keep them
 * cryptographically separate.
 *
 * **Joiner→Host** ([JoinerEnrollInfo]):
 * - the joiner's WG public key (so the host can add them as a peer).
 * - an optional human-readable device label.
 *
 * **Host→Joiner** ([HostEnrollInfo]):
 * - host's WG public key (for the joiner's `[Peer] PublicKey`).
 * - host's WG endpoint address (`ip:port` for `[Peer] Endpoint`).
 * - the joiner's pre-allocated address (e.g. `10.99.0.2/32`,
 * for the joiner's `[Interface] Address`).
 * - allowed-IPs (subnet the joiner can reach via the tunnel).
 * - optional broker WSS + key + salt: where the joiner should
 * subscribe for OFFER updates after enrollment. Falls back to
 * the app's default broker (settings) if absent.
 * - assorted wg-quick conveniences (DNS, MTU, keepalive).
 *
 * Both schemas carry `v` (protocol version) and `ts` (UTC seconds)
 * for replay-resistance, mirroring the existing ENROLL plaintext
 * pattern.
 */
@Serializable
data class JoinerEnrollInfo(
    @SerialName("v") val version: Int = PROTOCOL_VERSION,
    @SerialName("ts") val timestamp: Long,
    @SerialName("wg_pubkey") val wgPubkeyB64: String,
    @SerialName("device_name") val deviceName: String? = null,
)

@Serializable
data class HostEnrollInfo(
    @SerialName("v") val version: Int = PROTOCOL_VERSION,
    @SerialName("ts") val timestamp: Long,
    @SerialName("wg_pubkey") val wgPubkeyB64: String,
    @SerialName("wg_endpoint") val wgEndpoint: String,
    @SerialName("assigned_address") val assignedAddress: String,
    @SerialName("allowed_ips") val allowedIps: String,
    @SerialName("broker_wss") val brokerWss: String? = null,
    @SerialName("broker_key") val brokerKey: String? = null,
    @SerialName("salt") val saltB64: String? = null,
    @SerialName("dns") val dns: String? = null,
    @SerialName("mtu") val mtu: Int? = null,
    @SerialName("keepalive") val keepalive: Int? = null,
    @SerialName("host_name") val hostName: String? = null,
)

/** Round-trip codec: serialise to JSON, encrypt with [sharedKey] via
 * NaCl secretbox. The result is suitable for the `encryptedInfo`
 * field of [buildSasConfirmEnvelope]. */
fun encodeJoinerInfo(info: JoinerEnrollInfo, sharedKey: ByteArray): ByteArray {
    require(sharedKey.size >= 32) { "sharedKey too short" }
    val plain = SAS_INFO_JSON.encodeToString(JoinerEnrollInfo.serializer(), info)
    return secretboxEncrypt(plain.toByteArray(Charsets.UTF_8), sharedKey.copyOfRange(0, 32))
}

fun encodeHostInfo(info: HostEnrollInfo, sharedKey: ByteArray): ByteArray {
    require(sharedKey.size >= 32) { "sharedKey too short" }
    val plain = SAS_INFO_JSON.encodeToString(HostEnrollInfo.serializer(), info)
    return secretboxEncrypt(plain.toByteArray(Charsets.UTF_8), sharedKey.copyOfRange(0, 32))
}

/** Decrypt an inbound encryptedInfo blob. Returns null on any
 * failure (wrong key, malformed JSON, unsupported version, stale
 * timestamp). Silent failures are deliberate — error shapes
 * shouldn't be observable to a network attacker. */
fun decodeJoinerInfo(
    blob: ByteArray,
    sharedKey: ByteArray,
    nowEpochSeconds: Long = System.currentTimeMillis() / 1000,
    freshnessWindowSeconds: Long = PROTOCOL_FRESHNESS_WINDOW_SECONDS,
): JoinerEnrollInfo? {
    if (sharedKey.size < 32) return null
    val plain = secretboxDecrypt(blob, sharedKey.copyOfRange(0, 32)) ?: return null
    val info = try {
        SAS_INFO_JSON.decodeFromString(JoinerEnrollInfo.serializer(),
            plain.toString(Charsets.UTF_8))
    } catch (_: Exception) { return null }
    if (info.version != PROTOCOL_VERSION) return null
    if (kotlin.math.abs(nowEpochSeconds - info.timestamp) > freshnessWindowSeconds) return null
    if (info.wgPubkeyB64.let { isValidWgPubkey(it).not() }) return null
    return info
}

fun decodeHostInfo(
    blob: ByteArray,
    sharedKey: ByteArray,
    nowEpochSeconds: Long = System.currentTimeMillis() / 1000,
    freshnessWindowSeconds: Long = PROTOCOL_FRESHNESS_WINDOW_SECONDS,
): HostEnrollInfo? {
    if (sharedKey.size < 32) return null
    val plain = secretboxDecrypt(blob, sharedKey.copyOfRange(0, 32)) ?: return null
    val info = try {
        SAS_INFO_JSON.decodeFromString(HostEnrollInfo.serializer(),
            plain.toString(Charsets.UTF_8))
    } catch (_: Exception) { return null }
    if (info.version != PROTOCOL_VERSION) return null
    if (kotlin.math.abs(nowEpochSeconds - info.timestamp) > freshnessWindowSeconds) return null
    if (info.wgPubkeyB64.let { isValidWgPubkey(it).not() }) return null
    return info
}

/** True iff [s] decodes to exactly 32 bytes via standard-base64.
 * Defensive validation — a malicious peer that constructed the
 * same SPAKE2 password (out-of-band leak) shouldn't be able to
 * trick us into accepting a junk pubkey. */
private fun isValidWgPubkey(s: String): Boolean = try {
    Base64.getDecoder().decode(s).size == 32
} catch (_: Exception) { false }

/** JSON for SAS info — encodeDefaults so optional fields with
 * default values still serialise (matches the existing ENROLL
 * plaintext convention). */
private val SAS_INFO_JSON = Json {
    ignoreUnknownKeys = true
    encodeDefaults = true
}
