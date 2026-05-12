package com.gutschke.wgrtc.data

import java.util.Base64

/**
 * Parsed view of a wireguard-go IpcGet UAPI dump. The host
 * backend asks `wgbridge_native` for this string at sample time,
 * hands it to [UapiStatsParser.parse], and feeds the result into
 * the throughput / peer-stats flows the status line drives.
 *
 * Pubkey hex → standard-base64 conversion happens here. UAPI
 * emits per-peer keys as hex; the rest of the app keys peers by
 * standard-base64 (matching the wg-quick text format).
 */
data class UapiStats(
    val listenPort: Int? = null,
    /** Total bytes received across all peers since the device came up. */
    val totalRxBytes: Long = 0L,
    /** Total bytes transmitted across all peers since the device came up. */
    val totalTxBytes: Long = 0L,
    /** Per-peer slice keyed by standard-base64 public key. */
    val peers: Map<String, PeerStats> = emptyMap(),
) {
    /** Highest non-null handshake epoch across the peer set, or null
     * if no peer has ever completed a handshake. Drives the
     * tunnel-level "Last handshake N s ago" line in the status hero. */
    val mostRecentHandshakeEpochMs: Long?
        get() = peers.values
            .mapNotNull { it.lastHandshakeEpochMs }
            .maxOrNull()
}

/**
 * UAPI parser. Pure function — input is the raw IpcGet string,
 * output is a [UapiStats]. Tolerant of CRLF / LF, blank lines,
 * unknown keys, and the trailing `errno=0` that wireguard-go
 * appends. See [UapiStatsParserTest] for the format examples this
 * was built against.
 */
object UapiStatsParser {

    fun parse(uapi: String): UapiStats {
        var listenPort: Int? = null
        var totalRx = 0L
        var totalTx = 0L
        val peers = LinkedHashMap<String, PeerStats>()

        // Per-peer accumulator, flushed each time we see a new
        // `public_key=` line (or at end-of-document).
        var curKey: String? = null
        var curRx = 0L
        var curTx = 0L
        var curHandshakeMs: Long? = null

        fun flushPeer() {
            val k = curKey ?: return
            peers[k] = PeerStats(
                rxBytes = curRx,
                txBytes = curTx,
                lastHandshakeEpochMs = curHandshakeMs,
            )
            totalRx += curRx
            totalTx += curTx
            // Reset accumulators for the next peer.
            curKey = null
            curRx = 0L
            curTx = 0L
            curHandshakeMs = null
        }

        for (rawLine in uapi.lineSequence()) {
            val line = rawLine.trim()
            if (line.isEmpty()) continue
            val eq = line.indexOf('=')
            if (eq < 0) continue
            val key = line.substring(0, eq).trim()
            val value = line.substring(eq + 1).trim()
            when (key) {
                "public_key" -> {
                    flushPeer()
                    curKey = hexToBase64(value) ?: continue
                }
                "listen_port" -> {
                    if (curKey == null) listenPort = value.toIntOrNull()
                }
                "tx_bytes" -> if (curKey != null) curTx = value.toLongOrNull() ?: 0L
                "rx_bytes" -> if (curKey != null) curRx = value.toLongOrNull() ?: 0L
                "last_handshake_time_sec" -> {
                    if (curKey != null) {
                        val sec = value.toLongOrNull() ?: 0L
                        curHandshakeMs = if (sec == 0L) null
                            else sec * 1000L + (curHandshakeMs?.let { it % 1000L } ?: 0L)
                    }
                }
                "last_handshake_time_nsec" -> {
                    if (curKey != null) {
                        val nsec = value.toLongOrNull() ?: 0L
                        val msFromNsec = nsec / 1_000_000L
                        curHandshakeMs = curHandshakeMs?.let {
                            // Drop any prior fractional part, replace with this nsec-derived ms.
                            (it / 1000L) * 1000L + msFromNsec
                        }
                        // If sec=0 (never handshook), don't promote nsec → null stays null.
                    }
                }
                // Other UAPI keys — fwmark, allowed_ip, endpoint,
                // persistent_keepalive_interval, errno — ignored.
            }
        }
        flushPeer()
        return UapiStats(
            listenPort = listenPort,
            totalRxBytes = totalRx,
            totalTxBytes = totalTx,
            peers = peers,
        )
    }

    /** Hex-decode a 32-byte pubkey and return its standard-base64
     * encoding. Returns null for malformed input — that peer is
     * skipped rather than crashing the parse. */
    private fun hexToBase64(hex: String): String? {
        if (hex.length != 64) return null
        val bytes = ByteArray(32)
        for (i in 0 until 32) {
            val hi = Character.digit(hex[2 * i], 16)
            val lo = Character.digit(hex[2 * i + 1], 16)
            if (hi < 0 || lo < 0) return null
            bytes[i] = ((hi shl 4) or lo).toByte()
        }
        return Base64.getEncoder().encodeToString(bytes)
    }
}
