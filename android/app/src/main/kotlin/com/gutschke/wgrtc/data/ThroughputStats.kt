package com.gutschke.wgrtc.data

/**
 * Snapshot of a tunnel's transfer counters plus the per-second rate
 * computed from the previous sample. All sampling lives in
 * `WgrtcViewModel`; this file is just the value type plus the two
 * formatters the UI uses.
 *
 * Units are "decimal" (1 KB = 1000 B) to match what most network
 * tooling shows. Switching to binary prefixes (KiB / MiB) would be a
 * one-line change here, but the consensus among comparable WireGuard
 * clients is decimal — sticking with that for parity.
 */
data class ThroughputStats(
    val rxBytes: Long,
    val txBytes: Long,
    val rxBytesPerSec: Double,
    val txBytesPerSec: Double,
    /** Most recent handshake across all peers on this tunnel, or null
     * when no handshake has happened (kernel reports 0 → null).
     * Epoch milliseconds. */
    val lastHandshakeEpochMs: Long? = null,
)

/** Per-peer slice of the same WG statistics. Used by host-mode
 * tunnel detail to surface "Last handshake N s ago" / "Never
 * connected" next to each enrolled peer — the most efficient way
 * to diagnose "tunnel is up but no traffic" cases (the per-peer
 * handshake age separates "wrong endpoint / firewall / lost
 * packets" from "wrong pubkey / config drift"). Map key is the
 * peer's standard-base64 public key, matching
 * [EnrolledPeer.pubkeyB64]. */
data class PeerStats(
    val rxBytes: Long,
    val txBytes: Long,
    /** Epoch-ms of the peer's most recent successful handshake, or
     * null if the peer has never completed one. */
    val lastHandshakeEpochMs: Long?,
)

/** Format a byte count.
 *
 * Decimal SI prefixes (1 KB = 1 000 B) to match what most network
 * tooling and comparable WireGuard clients show. Thresholds are tuned
 * so the displayed value ticks *visibly* under normal traffic — bytes
 * precision up to 100 KB, then KB precision up to 100 MB, then floating
 * MB / GB. Without this a slow flow (e.g. one ping per second ≈ 84 B/s)
 * would freeze the readout at "1 KB" for 12 s before the next 1 KB
 * increment, which made the status panel look broken during demos. */
fun formatBytes(bytes: Long): String = when {
    bytes < 100_000L -> "%,d B".format(bytes)
    bytes < 100_000_000L -> "%,d KB".format(bytes / 1_000L)
    bytes < 1_000_000_000L -> "%.1f MB".format(bytes / 1_000_000.0)
    bytes < 100_000_000_000L -> "%,d MB".format(bytes / 1_000_000L)
    else -> "%.1f GB".format(bytes / 1_000_000_000.0)
}

/**
 * Format a "Last handshake: …" sub-string. Inputs:
 * - [lastHandshakeEpochMs] = `null` or `0L` → "never" (kernel reports 0 when
 * the WG handshake hasn't fired yet for this peer);
 * - otherwise a relative form: "12s ago", "2m 45s ago", "1h 3m ago".
 *
 * Pure function — `nowMs` is overridable so the formatter is
 * independent-of-clock testable.
 */
fun formatHandshakeAgo(
    lastHandshakeEpochMs: Long?,
    nowMs: Long = System.currentTimeMillis(),
): String {
    if (lastHandshakeEpochMs == null || lastHandshakeEpochMs <= 0) return "never"
    val deltaSec = ((nowMs - lastHandshakeEpochMs) / 1000).coerceAtLeast(0)
    return when {
        deltaSec < 60 -> "${deltaSec}s ago"
        deltaSec < 3600 -> "${deltaSec / 60}m ${deltaSec % 60}s ago"
        deltaSec < 86_400 -> "${deltaSec / 3600}h ${(deltaSec % 3600) / 60}m ago"
        else -> "${deltaSec / 86_400}d ${(deltaSec % 86_400) / 3600}h ago"
    }
}

/** Format a per-second rate. Same precision scheme as [formatBytes]
 * — bytes precision up to 10 KB/s so a low-flow demo (a one-per-second
 * ping ≈ 84 B/s) reads as "84 B/s" instead of rounding to "0 KB/s". */
fun formatRate(bytesPerSec: Double): String {
    val v = bytesPerSec.toLong()
    return when {
        v < 10_000L -> "%,d B/s".format(v)
        v < 10_000_000L -> "%,d KB/s".format(v / 1_000L)
        v < 1_000_000_000L -> "%.1f MB/s".format(v / 1_000_000.0)
        else -> "%.1f GB/s".format(v / 1_000_000_000.0)
    }
}
