package com.gutschke.wgrtc.data

import java.io.IOException
import java.net.InetSocketAddress

/**
 * Parse a "host:port" string of the shape gomobile / Go's
 * net.Addr.String() returns ("10.99.0.2:54321" or "[fd00::1]:443")
 * into an [InetSocketAddress]. Throws [IOException] on malformed
 * input — these values come from the wgbridge native side, where
 * "wrong shape" is a programming error, but the tests want a
 * predictable exception type.
 */
internal fun parseHostPort(s: String): InetSocketAddress {
    val colon = s.lastIndexOf(':')
    if (colon < 0) throw IOException("invalid host:port from wgbridge: $s")
    val host = s.substring(0, colon).removeSurrounding("[", "]")
    val port = s.substring(colon + 1).toIntOrNull()
        ?: throw IOException("invalid port in host:port: $s")
    return InetSocketAddress.createUnresolved(host, port)
}
