package com.gutschke.wgrtc.signalling

import java.net.URLDecoder
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import java.util.Base64

/**
 * Parsed `wgrtc-enroll://v1?...` URI. Field semantics match
 * the internal design doc
 *
 * **Trust model — read before adding fields.** The URI is admin-issued
 * and arrives at the client via an out-of-band channel (QR, paste,
 * messaging app). An attacker who can rewrite the URI in transit can
 * swap any field. The protocol therefore distinguishes two kinds of
 * field:
 *
 * - **Security-bearing** — `pk`, `salt`, `token`, `broker`, `brokerkey`.
 * A forged value here either drops messages into the void (broker
 * routes to a non-existent peer), pins the client to an
 * attacker-controlled broker (which still can't decrypt without the
 * legit server's private key), or fails authentication at the
 * daemon (token mismatch, X25519-ECDH mismatch). The daemon is the
 * enforcement point. None of these can be relaxed by a malicious
 * URI.
 *
 * - **Hint-only** — `expires`, `server`, and any future field that
 * only steers UX or short-circuits round-trips. These MUST NOT be
 * used as a security boundary. A forged `expires=99999999999`
 * bypasses [EnrollClient]'s local fast-fail check; the daemon still
 * silently drops the request via its own authoritative
 * `expires_at` in `pending-tokens.json`.
 *
 * If you ever find yourself reading `expiresAt` (or `serverName`) in
 * code that decides whether to *trust* something, stop — that's a
 * design break. Move the check to the daemon and have it propagate
 * the result via the encrypted ENROLL_OK / ENROLL_ERR plaintext.
 *
 * Implementation note: this module deliberately avoids `android.net.Uri`
 * and `android.util.Base64` so that pure-JVM unit tests can exercise it
 * without Robolectric or instrumentation. The URL spec we parse is a
 * narrow subset (`scheme://host?key=value&key=value`) and predictable
 * enough that a hand-rolled split + URLDecoder is sufficient.
 */
data class EnrollUri(
 val serverPub: ByteArray,
 val salt: ByteArray,
 val brokerWss: String,
 val brokerKey: String,
 val token: ByteArray,
 val expiresAt: Long?,
 val serverName: String?,
) {
 companion object {
 @Throws(IllegalArgumentException::class)
 fun parse(uri: String): EnrollUri {
 val (scheme, rest) = uri.split("://", limit = 2).let {
 require(it.size == 2) { "not a URI: $uri" }
 it[0] to it[1]
 }
 require(scheme == "wgrtc-enroll") {
 "not a wgrtc-enroll:// URI: $uri"
 }
 val (host, query) = rest.split("?", limit = 2).let {
 if (it.size == 2) it[0] to it[1] else it[0] to ""
 }
 require(host == "v1") {
 "unsupported version: $host (expected v1)"
 }
 val params = parseQuery(query)
 fun req(name: String): String = params[name]
 ?: throw IllegalArgumentException("missing required field $name")
 return EnrollUri(
 serverPub = b64UrlDecode(req("pk")),
 salt = b64UrlDecode(req("salt")),
 brokerWss = req("broker"),
 brokerKey = params["brokerkey"] ?: "peerjs",
 token = b64UrlDecode(req("token")),
 expiresAt = params["expires"]?.toLongOrNull(),
 serverName = params["server"],
 )
 }

 private fun parseQuery(query: String): Map<String, String> {
 if (query.isEmpty()) return emptyMap()
 // First-occurrence-wins, matching android.net.Uri.getQueryParameter.
 val out = LinkedHashMap<String, String>()
 for (pair in query.split('&')) {
 if (pair.isEmpty()) continue
 val eq = pair.indexOf('=')
 val (k, v) = if (eq < 0) pair to "" else
 pair.substring(0, eq) to pair.substring(eq + 1)
 val key = URLDecoder.decode(k, StandardCharsets.UTF_8)
 val value = URLDecoder.decode(v, StandardCharsets.UTF_8)
 if (key !in out) out[key] = value
 }
 return out
 }

 private fun b64UrlDecode(s: String): ByteArray {
 // Accept both padded and unpadded forms; the URI spec drops
 // padding but copy-paste from other tooling sometimes keeps it.
 val padded = when (s.length % 4) {
 0 -> s
 2 -> "$s=="
 3 -> "$s="
 else -> throw IllegalArgumentException(
 "invalid base64url length: ${s.length}")
 }
 return Base64.getUrlDecoder().decode(padded)
 }

 /**
 * Reverse of [parse]: render a `wgrtc-enroll://v1?...` URI from
 * raw materials. Used by host-mode (the phone mints
 * its own URI when the user creates an enrollment QR).
 *
 * Hard requirements:
 * - [serverPub], [salt], [token] must each be exactly 32 bytes
 * (the WireGuard / token convention). Wrong-length input
 * throws — better to fail loudly than emit a URI that any
 * parser will reject.
 * - [brokerWss] is URL-encoded; arbitrary URL characters
 * survive the round-trip through [parse].
 * - [brokerKey] is always emitted (even when equal to the
 * `peerjs` default) — predictable round-trip beats a
 * micro-shorter URI.
 * - [expiresAt] / [serverName] are optional and omitted when
 * null. Hint-only fields per the trust model — see
 * class-level kdoc.
 */
 fun build(
 serverPub: ByteArray,
 salt: ByteArray,
 brokerWss: String,
 brokerKey: String,
 token: ByteArray,
 expiresAt: Long? = null,
 serverName: String? = null,
 ): String {
 require(serverPub.size == 32) {
 "serverPub must be 32 bytes, got ${serverPub.size}"
 }
 require(salt.size == 32) {
 "salt must be 32 bytes, got ${salt.size}"
 }
 require(token.size == 32) {
 "token must be 32 bytes, got ${token.size}"
 }
 val sb = StringBuilder("wgrtc-enroll://v1?")
 sb.append("pk=").append(b64UrlEncode(serverPub))
 sb.append("&salt=").append(b64UrlEncode(salt))
 sb.append("&broker=").append(urlEncode(brokerWss))
 sb.append("&brokerkey=").append(urlEncode(brokerKey))
 sb.append("&token=").append(b64UrlEncode(token))
 if (expiresAt != null) sb.append("&expires=").append(expiresAt)
 if (serverName != null) sb.append("&server=").append(urlEncode(serverName))
 return sb.toString()
 }

 private val b64UrlNoPad = Base64.getUrlEncoder().withoutPadding()
 private fun b64UrlEncode(bytes: ByteArray): String =
 b64UrlNoPad.encodeToString(bytes)
 private fun urlEncode(s: String): String =
 URLEncoder.encode(s, StandardCharsets.UTF_8)
 }
}
