package com.gutschke.wgrtc.data

import com.gutschke.wgrtc.signalling.EnrollErrPlain
import com.gutschke.wgrtc.signalling.EnrollOkPlain
import com.gutschke.wgrtc.signalling.EndpointCandidate
import com.gutschke.wgrtc.signalling.InboundEnrollEnvelope
import com.gutschke.wgrtc.signalling.PROTOCOL_FRESHNESS_WINDOW_SECONDS
import com.gutschke.wgrtc.signalling.PROTOCOL_VERSION
import com.gutschke.wgrtc.signalling.buildEnrollResponseEnvelope
import com.gutschke.wgrtc.signalling.deriveEnrollKey
import com.gutschke.wgrtc.signalling.routingId
import com.gutschke.wgrtc.signalling.secretboxDecrypt
import com.gutschke.wgrtc.signalling.secretboxEncrypt
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.util.Base64
import kotlin.math.abs

/**
 * inbound ENROLL handler. Mirror of the daemon's
 * `_handle_enroll` in `github/wireguardrtc`.
 *
 * Pure logic — no I/O, no broker WSS. Caller (a host-mode
 * `OfferListener` or a dedicated host service) feeds in the parsed
 * inbound envelope plus the current [HostState], and gets back a
 * [Result] describing what to send and what to persist.
 *
 * Threat-model contract: failures are SILENT where they reveal which
 * step failed (no-such-token vs wrong-key vs expired-token vs stale
 * timestamp all return [Result.Ignore]). The only authenticated
 * negative is `enroll_err code=TOKEN_USED`, which we send precisely
 * because the user-noticing property in the internal design doc wants it
 * surfaced in the client UI.
 */
class InboundEnrollHandler(
 private val tokens: PendingTokensStore,
 private val nowMs: () -> Long = { System.currentTimeMillis() },
 private val nowSec: () -> Long = { nowMs() / 1000 },
 private val freshnessWindowSec: Long = PROTOCOL_FRESHNESS_WINDOW_SECONDS,
) {

 /**
 * Snapshot of the host's WG state the handler needs to construct
 * a response. Caller assembles this fresh per request.
 */
 data class HostState(
 /** 32-byte raw private key for the host's WG iface. */
 val serverPrivBytes: ByteArray,
 /** Standard-base64 form of the matching public key. Cached
 * here so we don't have to recompute on every request. */
 val serverPubB64: String,
 /** UDP port wg-go is listening on. Goes into
 * `server_endpoint_hint`. */
 val listenPort: Int,
 /** Host's address inside the WG subnet (e.g., 10.99.0.1). */
 val hostIp: String,
 /** Subnet to allocate client IPs from (e.g., 10.99.0.0/24). */
 val subnet: String,
 /** Salt for the routing-id calculation; mirror of daemon. */
 val saltBytes: ByteArray,
 /** Optional public-IP:port the host wants to advertise as the
 * primary endpoint hint. Null elides the field. */
 val publicEndpointHint: String? = null,
 /** Pre-computed candidate list to ship in `enroll_ok.candidates`. */
 val candidates: List<EndpointCandidate> = emptyList(),
 /** Currently-allocated peer IPs (so we don't double-assign). */
 val allocatedIps: Set<String> = emptySet(),
 /** V6.3 — per-tunnel v6 ULA `/64` (e.g. `fd1a:2b3c:4d5e::/64`).
  * Null on tunnels persisted before V6.2 existed. */
 val subnetV6: String? = null,
 /** V6.3 — host's v6 address inside [subnetV6] (e.g.
  * `fd1a:2b3c:4d5e::1`).  Null iff [subnetV6] is null. */
 val hostIpV6: String? = null,
 /** V6.3 — currently-allocated peer v6 IPs (sibling of
  * [allocatedIps]). */
 val allocatedIpsV6: Set<String> = emptySet(),
 /** What the *client* puts in its `[Peer] AllowedIPs` line.
 * Mirror of daemon default — NAT or
 * Cascade both want all client traffic through the tunnel;
 * future settings will let users narrow this.
 * Canonical (no whitespace) for ChromeOS compatibility —
 * see [WgAllowedIps]. */
 val clientAllowedIps: String = WgAllowedIps.FULL_TUNNEL,
 /** Persistent-keepalive seconds advised to the client. */
 val keepalive: Int = 25,
 )

 data class NewPeer(
 val pubkeyB64: String,
 val assignedIp: String,
 val nameHint: String,
 /** Manual-flow only: the wg-quick text the host minted for
 * this peer. Stored on the persisted [EnrolledPeer] so
 * the host UI's "Show invitation" action survives an app
 * restart. Null for QR / wormhole enrollments where the
 * joiner generated its own keypair (see
 * [EnrolledPeer.manualInvitationText] for the security
 * trade-off). */
 val manualInvitationText: String? = null,
 /** V6.3 — per-peer v6 address inside the host's `subnetV6`.
  * Null when the host tunnel has no v6 subnet (legacy v4-only)
  * OR when V6.3 allocation hasn't been wired into the calling
  * path yet.  Persisted on [EnrolledPeer.assignedIpV6]. */
 val assignedIpV6: String? = null,
 )

 sealed interface Result {
 /** Reply with [envelopeJson]; if [newPeer] is non-null the
 * caller MUST persist it to the host-mode tunnel and trigger
 * a wg-go reconfig before the response is delivered. */
 data class Reply(val envelopeJson: String, val newPeer: NewPeer?) : Result

 /** Silent ignore. Caller logs at debug. Reason is for
 * diagnostics only — never echoed onto the wire. */
 data class Ignore(val reason: String) : Result
 }

 fun handle(env: InboundEnrollEnvelope, host: HostState): Result {
 val now = nowSec()

 // 1. Decode + length-check client_pub.
 val clientPubBytes = try {
 Base64.getDecoder().decode(env.clientPubB64)
 } catch (_: Exception) {
 return Result.Ignore("client_pub b64 decode failed")
 }
 if (clientPubBytes.size != 32) {
 return Result.Ignore("client_pub wrong length: ${clientPubBytes.size}")
 }

 // 2. src must equal routing_id(client_pub, salt). Sanity guard
 // against malformed messages; broker sets src so an attacker
 // can't forge it through the broker, but defense-in-depth.
 val expectedSrc = routingId(env.clientPubB64, host.saltBytes)
 if (env.src != expectedSrc) {
 return Result.Ignore("src mismatch (got=${env.src.takeLast(8)}, expected=${expectedSrc.takeLast(8)})")
 }

 // 3. Try-decrypt with each token, including ones that have
 // been consumed but not yet purged. We need consumed
 // matches because a re-enrollment with the same auth-tagged
 // blob deserves an authenticated `TOKEN_USED` reply so the
 // client UI can surface the race-loss (mirror of the
 // daemon's [_handle_enroll]).
 val candidates = tokens.listAll(now = nowMs())
 var matched: PendingTokensStore.PendingToken? = null
 var matchedKey: ByteArray? = null
 for (entry in candidates) {
 val key = try {
 deriveEnrollKey(host.serverPrivBytes, clientPubBytes, entry.tokenSecret)
 } catch (_: Exception) { continue }
 val ct = try {
 Base64.getDecoder().decode(env.blobB64)
 } catch (_: Exception) {
 return Result.Ignore("blob b64 decode failed")
 }
 val plainBytes = secretboxDecrypt(ct, key) ?: continue
 val plain = try {
 Json.parseToJsonElement(plainBytes.toString(Charsets.UTF_8)) as? JsonObject
 } catch (_: Exception) { null } ?: continue
 // Belt-and-braces: ENROLL plaintext must echo the token
 // base64 in `token_check`. Authenticated ciphertext already
 // proves the sender held the token; this catches confused-
 // deputy bugs (an attacker who somehow got an auth tag from
 // a different protocol context).
 val tokenCheck = (plain["token_check"] as? JsonPrimitive)?.content
 // Wire convention: token_check is STANDARD base64 with
 // padding (matches the daemon + the Android EnrollClient's
 // b64StdEncode of the URI token bytes). PendingTokensStore
 // uses URL-safe-no-padding internally for cleaner JSON;
 // re-encode here to compare on the wire format.
 val expectedCheck = b64Std.encodeToString(entry.tokenSecret)
 if (tokenCheck != expectedCheck) continue
 // Freshness: ts must be within ±freshnessWindow of now.
 val ts = (plain["ts"] as? JsonPrimitive)?.content?.toLongOrNull() ?: continue
 if (abs(now - ts) > freshnessWindowSec) continue
 matched = entry
 matchedKey = key
 break
 }

 if (matched == null || matchedKey == null) {
 return Result.Ignore("no matching token (or wrong key, or stale ts)")
 }

 // 4. If the matched token is already consumed, this is a
 // race-loss (different client beat us, or the same client
 // is retrying with a stale URI). Authenticated reply
 // surfaces the failure to the client UI.
 if (matched.consumed) {
 return Result.Reply(
 envelopeJson = encryptErrAndWrap(
 matchedKey, host, env.src, "TOKEN_USED",
 "token already consumed by another client", now),
 newPeer = null,
 )
 }

 // 5. Allocate the client IP BEFORE consuming the token. On
 // subnet exhaustion we want the user to be able to retry
 // after fixing the host config — burning the token would
 // force them to re-mint.
 val clientIp = HostSubnetAllocator.nextFreeIp(
 host.subnet, host.hostIp, host.allocatedIps,
 ) ?: return Result.Reply(
 envelopeJson = encryptErrAndWrap(
 matchedKey, host, env.src, "PROVISION_FAILED",
 "host-mode subnet ${host.subnet} exhausted", now),
 newPeer = null,
 )
 // V6.3 — allocate the v6 sibling iff the host advertised
 // a v6 subnet.  Soft-fail: if v6 allocation fails (only
 // realistic on a wildly over-subscribed subnet or a
 // malformed prefix), fall through to v4-only so the
 // enrollment still succeeds.  The dual-stack joiner just
 // gets a v4-only tunnel in that pathological case.
 val clientIpV6: String? = if (host.subnetV6 != null && host.hostIpV6 != null) {
 HostSubnetAllocator.nextFreeIpV6(
 host.subnetV6, host.hostIpV6, host.allocatedIpsV6)
 } else null

 // 6. Atomic claim. consume() returns null if some other
 // request raced us between listAll() and here — in that
 // case the other request is the legitimate one; we send
 // TOKEN_USED.
 val claimed = tokens.consume(matched.tokenSecret, nowMs())
 if (claimed == null) {
 return Result.Reply(
 envelopeJson = encryptErrAndWrap(
 matchedKey, host, env.src, "TOKEN_USED",
 "token consumed by a concurrent enrollment", now),
 newPeer = null,
 )
 }

 // 6. Build ENROLL_OK plaintext.
 // V6.3: when a v6 sibling is allocated, emit comma-
 // separated dual-stack on `address`.  Canonical form (no
 // whitespace) — see WgAllowedIps for ChromeOS rationale.
 val addressLine = if (clientIpV6 != null) {
 "$clientIp/32,$clientIpV6/128"
 } else {
 "$clientIp/32"
 }
 val ok = EnrollOkPlain(
 version = PROTOCOL_VERSION,
 timestamp = now,
 address = addressLine,
 allowedIps = host.clientAllowedIps,
 keepalive = host.keepalive,
 serverPubkey = host.serverPubB64,
 serverEndpointHint = host.publicEndpointHint,
 candidates = host.candidates.takeIf { it.isNotEmpty() },
 name = matched.nameHint,
 )
 val okBlob = encryptPlaintext(matchedKey, JSON.encodeToString(EnrollOkPlain.serializer(), ok))
 val envOut = buildEnrollResponseEnvelope(
 dstRoutingId = env.src,
 kind = "enroll_ok",
 serverPubBase64 = host.serverPubB64,
 blobBase64 = okBlob,
 )

 return Result.Reply(
 envelopeJson = envOut.toString(),
 newPeer = NewPeer(
 pubkeyB64 = env.clientPubB64,
 assignedIp = clientIp,
 nameHint = matched.nameHint,
 assignedIpV6 = clientIpV6,
 ),
 )
 }

 private fun encryptErrAndWrap(
 key: ByteArray, host: HostState, src: String,
 code: String, note: String, nowSec: Long,
 ): String {
 val err = EnrollErrPlain(
 version = PROTOCOL_VERSION,
 timestamp = nowSec,
 code = code,
 note = note,
 retryAfter = 0,
 )
 val blob = encryptPlaintext(key, JSON.encodeToString(EnrollErrPlain.serializer(), err))
 return buildEnrollResponseEnvelope(
 dstRoutingId = src,
 kind = "enroll_err",
 serverPubBase64 = host.serverPubB64,
 blobBase64 = blob,
 ).toString()
 }

 private fun encryptPlaintext(key: ByteArray, plaintext: String): String {
 val ct = secretboxEncrypt(plaintext.toByteArray(Charsets.UTF_8), key)
 return Base64.getEncoder().encodeToString(ct)
 }

 companion object {
 private val JSON = Json { encodeDefaults = true }
 private val b64Std = Base64.getEncoder()
 }
}

/** Overload of [deriveEnrollKey] that takes raw byte arrays (to match
 * this handler's HostState). The signalling-module variant takes
 * base64 strings; we re-route through the byte-array form. */
private fun deriveEnrollKey(
 serverPrivBytes: ByteArray, clientPubBytes: ByteArray, token: ByteArray,
): ByteArray = com.gutschke.wgrtc.signalling.deriveEnrollKey(
 myPriv = serverPrivBytes,
 peerPub = clientPubBytes,
 token = token,
)
