package com.gutschke.wgrtc.signalling

/**
 * Serialize an `(ip, port)` pair into a wg-quick-compatible
 * `host:port` string. IPv4 (no colons) is rendered verbatim
 * (`"1.2.3.4:51820"`); IPv6 literals (any colon present and not
 * already enclosed in brackets) are bracketed (`"[v6]:51820"`).
 *
 * This is the single canonical formatter the codebase calls before
 * a `(ip, port)` pair leaves the host: persisted into the wg-quick
 * `Endpoint = …` line, emitted as a `serverEndpointHint`, or shipped
 * inside an `EndpointCandidate` blob to a joiner. Without it, an
 * IPv6 candidate like `2001:db8::1` plus port `51820` would
 * concatenate to `2001:db8::1:51820` — ambiguous to the receiver's
 * "split on last colon" parser, which would happily treat the
 * trailing `:51820` as the port and leave a malformed address.
 *
 * Counterpart of [com.gutschke.wgrtc.data.parseEndpoint] (which also
 * understands the bracketed-v6 form). Adding both halves up-front so
 * the codebase doesn't acquire `"$ip:$port"` and `"[${ip}]:$port"`
 * variants that drift.
 */
fun formatEndpoint(ip: String, port: Int): String {
    val trimmed = ip.trim()
    return if (trimmed.startsWith("[") || ':' !in trimmed) {
        // Already bracketed, or no colons (IPv4 / hostname).
        "$trimmed:$port"
    } else {
        // Bare IPv6 literal — bracket it.
        "[$trimmed]:$port"
    }
}
