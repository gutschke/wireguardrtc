package com.gutschke.wgrtc.data

import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.State
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.InetAddress

/**
 * Split an `Endpoint = host:port` value into (host, port).
 *
 * Handles three forms:
 * `1.2.3.4:51820` → ("1.2.3.4", 51820)
 * `[2001:db8::1]:51820` → ("2001:db8::1", 51820)
 * `vpn.example.com:51820`→ ("vpn.example.com", 51820)
 *
 * Returns `null` when the input doesn't parse as `host:port`.
 */
fun parseEndpoint(raw: String): Pair<String, Int>? {
    val s = raw.trim()
    if (s.isEmpty()) return null
    val (host, portStr) = if (s.startsWith("[")) {
        val close = s.indexOf(']')
        if (close < 0 || s.length < close + 3 || s[close + 1] != ':') return null
        s.substring(1, close) to s.substring(close + 2)
    } else {
        val colon = s.lastIndexOf(':')
        if (colon < 0) return null
        s.substring(0, colon) to s.substring(colon + 1)
    }
    val port = portStr.toIntOrNull() ?: return null
    return host to port
}

/**
 * Composable side-effect that asynchronously reverse-resolves [host]
 * to a hostname and returns the result. Returns `null` while the
 * lookup is in flight, on failure, and when the input was already a
 * hostname (so the caller can render "host (10.0.0.1)" instead of
 * pointlessly duplicating it).
 *
 * Cached by the [host] key — re-renders with the same input don't
 * trigger another lookup. Safe to call with an IP literal or a
 * hostname; returns null in the hostname case to avoid noise.
 */
@Composable
fun rememberReverseDns(host: String?): State<String?> {
    val state = remember(host) { mutableStateOf<String?>(null) }
    LaunchedEffect(host) {
        if (host.isNullOrBlank()) return@LaunchedEffect
        // If the user already gave us a hostname (i.e. it has letters
        // or a hyphen), don't try to "re-resolve" — that would waste a
        // forward-DNS query and add nothing to the display.
        if (host.any { it.isLetter() || it == '-' }) return@LaunchedEffect
        state.value = withContext(Dispatchers.IO) {
            try {
                val addr = InetAddress.getByName(host)
                // canonicalHostName falls back to the IP literal when
                // there's no PTR record — distinguish that from a
                // genuine answer.
                val canonical = addr.canonicalHostName
                if (canonical.isNullOrBlank() || canonical == host) null
                else canonical
            } catch (_: Throwable) {
                null
            }
        }
    }
    return state
}
