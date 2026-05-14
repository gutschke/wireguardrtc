package com.gutschke.wgrtc.signalling

import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.URL
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/**
 * Opportunistic network-info helpers used to enrich the Network-check
 * panel: reverse DNS for an address, and ISP/ASN lookup via Team Cymru.
 *
 * Everything here is best-effort.  Lookups may fail or time out; the
 * UI shows the verdict immediately and these results trickle in
 * afterwards.  Callers should treat null as "no extra info, move on".
 */

/**
 * Reverse-DNS lookup for [ip], using the platform resolver.  Returns
 * null on timeout, network error, or "no PTR record" (the resolver
 * returns the original IP literal in that case — we filter that out
 * so the caller sees null and shows nothing).
 */
suspend fun reverseDns(ip: String, timeoutMs: Long = 3000): String? =
    withContext(Dispatchers.IO) {
        withTimeoutOrNull(timeoutMs) {
            try {
                val addr = InetAddress.getByName(ip)
                val name = addr.canonicalHostName
                // canonicalHostName returns the input IP literal when
                // no PTR exists.  Don't echo the address back as its
                // own "hostname".
                if (name == null || name.equals(ip, ignoreCase = true)) null
                else name
            } catch (_: Exception) {
                null
            }
        }
    }

/**
 * Look up the AS number + AS name owning [ip] via Team Cymru's
 * `origin.asn.cymru.com` / `origin6.asn.cymru.com` TXT records,
 * tunnelled through Google's DNS-over-HTTPS so we don't rely on the
 * platform resolver supporting TXT queries.  Returns a string like
 * `"AS29222 Sonic.net"` or null on any failure.
 *
 * Two round trips: one to map IP → AS, one to map AS → name.  Each
 * has its own short timeout.  The overall function is capped at
 * [timeoutMs] including both hops.
 */
suspend fun lookupIsp(ip: String, timeoutMs: Long = 5000): String? =
    withContext(Dispatchers.IO) {
        withTimeoutOrNull(timeoutMs) {
            val isV6 = ip.contains(':')
            val reversed = if (isV6) reverseIp6Nibbles(ip)
                           else reverseIp4(ip)
            reversed ?: return@withTimeoutOrNull null
            val originZone = if (isV6) "origin6.asn.cymru.com"
                             else "origin.asn.cymru.com"
            val originTxt = dohTxt("$reversed.$originZone")?.firstOrNull()
                ?: return@withTimeoutOrNull null
            // Format: "AS_NUM | PREFIX | CC | REGISTRY | ALLOC_DATE"
            // Some prefixes return multiple AS numbers space-separated
            // in the first field; pick the first.
            val asNum = originTxt.split('|').firstOrNull()
                ?.trim()
                ?.split(Regex("\\s+"))
                ?.firstOrNull()
                ?: return@withTimeoutOrNull null
            // Second hop: AS_NUM → human name.
            val asnTxt = dohTxt("AS$asNum.asn.cymru.com")?.firstOrNull()
            if (asnTxt != null) {
                // Format: "AS_NUM | CC | REGISTRY | ALLOC_DATE | AS_NAME"
                val parts = asnTxt.split('|').map { it.trim() }
                val name = parts.getOrNull(4)
                if (name.isNullOrBlank()) "AS$asNum"
                else "AS$asNum $name"
            } else {
                "AS$asNum"
            }
        }
    }

// ─── helpers ──────────────────────────────────────────────────────────

internal fun reverseIp4(ip: String): String? {
    val parts = ip.split('.')
    if (parts.size != 4) return null
    if (parts.any { p ->
            p.isEmpty() || p.toIntOrNull()?.let { it in 0..255 } != true
        }) return null
    return parts.reversed().joinToString(".")
}

/** Expand an IPv6 string into Cymru-style nibble-reversed form (no
 * trailing `.ip6.arpa`).  Returns null if [ip] isn't parseable. */
internal fun reverseIp6Nibbles(ip: String): String? {
    val addr = runCatching { InetAddress.getByName(ip) }.getOrNull()
        ?: return null
    val bytes = addr.address
    if (bytes.size != 16) return null
    val sb = StringBuilder(63)
    for (i in 15 downTo 0) {
        val b = bytes[i].toInt() and 0xFF
        val lo = b and 0x0F
        val hi = (b shr 4) and 0x0F
        sb.append(Integer.toHexString(lo))
        sb.append('.')
        sb.append(Integer.toHexString(hi))
        if (i > 0) sb.append('.')
    }
    return sb.toString()
}

private val DOH_JSON = Json { ignoreUnknownKeys = true }

private suspend fun dohTxt(name: String): List<String>? =
    withContext(Dispatchers.IO) {
        try {
            val url = URL("https://dns.google/resolve" +
                "?name=$name&type=TXT")
            val conn = url.openConnection() as HttpURLConnection
            conn.connectTimeout = 2500
            conn.readTimeout = 2500
            conn.setRequestProperty("Accept", "application/dns-json")
            val body = conn.inputStream.use {
                it.readBytes().decodeToString()
            }
            val root = DOH_JSON.parseToJsonElement(body).jsonObject
            val answer = root["Answer"] as? JsonArray ?: return@withContext null
            val out = mutableListOf<String>()
            for (entry in answer) {
                val data = (entry as? JsonObject)?.get("data")
                    ?.jsonPrimitive?.content ?: continue
                out += data.trim('"')
            }
            out
        } catch (_: Exception) {
            null
        }
    }
