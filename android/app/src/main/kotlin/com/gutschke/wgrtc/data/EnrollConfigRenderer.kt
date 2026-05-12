package com.gutschke.wgrtc.data

import com.gutschke.wgrtc.signalling.EnrollOkPlain
import com.gutschke.wgrtc.signalling.EnrollResult
import com.gutschke.wgrtc.signalling.EnrollUri
import java.util.Base64

/**
 * Pure function — formats an `[Interface]…[Peer]…` wg-quick block from
 * an [EnrollUri] and the daemon's [EnrollResult.Ok] response.
 *
 * Lives here (not on the ViewModel) so JVM unit tests can exercise it
 * without instantiating any Android infrastructure. The original
 * private method on `WgrtcViewModel` was a thin wrapper that pulled
 * `android.util.Base64` in for two `encodeToString` calls — both
 * adequately served by `java.util.Base64.getEncoder()` (the
 * NO_WRAP / NO_PAD-equivalent default behaviour matches what we
 * actually need: 44-char padded base64 of 32 raw bytes).
 *
 * Throws [IllegalStateException] when the daemon's reply omits the
 * `server_endpoint_hint`. for what the daemon must
 * include for the client to write a usable wg-quick block.
 */
fun renderEnrollConfig(uri: EnrollUri, ok: EnrollResult.Ok): String {
 val plain: EnrollOkPlain = ok.plaintext
 val endpoint = plain.serverEndpointHint
 ?: throw IllegalStateException(
 "ENROLL_OK has no server endpoint; daemon needs PublicIp or STUN")
 val serverPub = plain.serverPubkey
 ?: Base64.getEncoder().encodeToString(uri.serverPub)
 val clientPriv = Base64.getEncoder().encodeToString(ok.clientPrivKey)
 return buildString {
 appendLine("[Interface]")
 appendLine("PrivateKey = $clientPriv")
 appendLine("Address = ${plain.address}")
 plain.dns?.let { appendLine("DNS = $it") }
 plain.mtu?.let { appendLine("MTU = $it") }
 appendLine()
 appendLine("[Peer]")
 appendLine("PublicKey = $serverPub")
 appendLine("Endpoint = $endpoint")
 // ChromeOS rejects whitespace inside AllowedIPs — canonicalize
 // both the daemon-supplied value and the fallback default. See
 // [WgAllowedIps] for the rationale.
 val allowedIps = plain.allowedIps?.let { WgAllowedIps.canonicalize(it) }
 ?: WgAllowedIps.FULL_TUNNEL
 appendLine("AllowedIPs = $allowedIps")
 appendLine("PersistentKeepalive = ${plain.keepalive ?: 25}")
 }
}
