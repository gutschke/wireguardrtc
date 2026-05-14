package com.gutschke.wgrtc.data

import com.gutschke.wgrtc.signalling.EnrollOkPlain
import com.gutschke.wgrtc.signalling.EnrollResult
import com.gutschke.wgrtc.signalling.EnrollUri
import com.gutschke.wgrtc.signalling.formatEndpoint
import com.gutschke.wgrtc.signalling.preferV6WithinKind
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
 * NO_WRAP / NO_PAD-equivalent default behavior matches what we
 * actually need: 44-char padded base64 of 32 raw bytes).
 *
 * Endpoint resolution order:
 *   1. `server_endpoint_hint` (the host's preferred contact address) —
 *      typically the STUN-discovered public IP, set when the host is
 *      behind a cone NAT.
 *   2. First entry of `candidates` — the host's full ranked list (LAN,
 *      STUN, PublicIp, mesh). Used when the host has no usable public
 *      endpoint (symmetric NAT, classification still in progress, or
 *      a phone-host on a network whose external IP it can't discover).
 *   3. Throw — neither a hint nor any candidate to write into the
 *      persisted `Endpoint =` line.
 *
 * The listener-driven OFFER mechanism rewrites the persisted endpoint
 * once the tunnel is live and a fresh candidate list arrives, so the
 * value written here only needs to be one usable address. A LAN-only
 * candidate is fine as the bootstrap entry.
 */
fun renderEnrollConfig(uri: EnrollUri, ok: EnrollResult.Ok): String {
 val plain: EnrollOkPlain = ok.plaintext
 // V6.A1: within each kind tier of the candidates list, prefer
 // IPv6 (RFC 8305 happy-eyeballs).  The host's overall rank
 // ordering (stun before lan, etc.) is preserved; only the
 // within-tier family preference flips when both families are
 // advertised at the same tier.
 val candidatesV6First = plain.candidates?.let(::preferV6WithinKind)
 val endpoint = plain.serverEndpointHint
 ?: candidatesV6First?.firstOrNull()?.let { formatEndpoint(it.ip, it.port) }
 ?: throw IllegalStateException(
 "ENROLL_OK has no server endpoint; host needs PublicIp or STUN " +
 "discovery to advertise a usable address")
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
