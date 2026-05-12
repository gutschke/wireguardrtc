package com.gutschke.wgrtc.data

import android.net.Network
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import android.system.StructPollfd
import android.util.Log
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import java.io.FileDescriptor
import java.io.IOException
import java.net.InetAddress
import java.nio.ByteBuffer

/**
 * **Unprivileged ICMPv4 ping for diagnostics.**
 *
 * Uses Linux's `SOCK_DGRAM/IPPROTO_ICMP` socket family (a "ping
 * socket"), accessible to ANY unprivileged process whose UID
 * falls inside `/proc/sys/net/ipv4/ping_group_range`. On Android
 * 8+ that range is `0 2147483647` (the full UID space) so every
 * app can do real ICMP without root.
 *
 * The kernel does most of the heavy lifting:
 *
 * - Writes the IPv4 header on outgoing packets.
 * - Rewrites the ICMP identifier on outgoing packets to a
 * per-socket value (we don't need to manage one).
 * - Validates the inbound ICMP checksum.
 * - Routes inbound echo replies back to the originating socket
 * based on the kernel-assigned identifier.
 *
 * We just build the ICMP message (type, code, identifier
 * placeholder, sequence, payload), `sendto` it, `poll` for the
 * reply, `recvfrom` to receive, and parse the type/sequence to
 * confirm.
 *
 * **Optional Network binding** ([network]). Used by the egress
 * policy: when the user picked "Wi-Fi only", we bind the ping
 * socket to the Wi-Fi `Network` so the diagnostic traffic
 * follows the same path the user's tunnel traffic would.
 *
 * **Threading.** All socket I/O happens on an IO dispatcher
 * (configurable for tests). Methods are `suspend fun`s — the
 * caller scopes them per UI action.
 */
class IcmpPinger(
    private val network: Network? = null,
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO,
    private val tag: String = "wgrtc-icmp-ping",
) {

    data class PingResult(
        val packetsSent: Int,
        val packetsReceived: Int,
        val rttsMs: List<Long>,
        val errorMessage: String? = null,
    ) {
        val packetLossPct: Int
            get() = if (packetsSent == 0) 0
            else ((packetsSent - packetsReceived) * 100 / packetsSent)
        val avgRttMs: Long? get() = if (rttsMs.isEmpty()) null
            else rttsMs.average().toLong()
        val minRttMs: Long? get() = rttsMs.minOrNull()
        val maxRttMs: Long? get() = rttsMs.maxOrNull()

        companion object {
            fun fatal(error: String): PingResult =
                PingResult(packetsSent = 0, packetsReceived = 0,
                    rttsMs = emptyList(), errorMessage = error)
        }
    }

    /** Single-shot ping. Returns RTT in ms on success, null on
     * timeout / error. Convenience wrapper around [pingMany]. */
    suspend fun pingOnce(dest: InetAddress, timeoutMs: Int = 1000): Long? =
        pingMany(dest, count = 1, intervalMs = 0, timeoutMs = timeoutMs)
            .rttsMs.firstOrNull()

    /**
     * Send [count] echo requests at [intervalMs] cadence,
     * waiting up to [timeoutMs] for each reply. Returns a
     * [PingResult] summarising the run. If the socket couldn't
     * be opened at all (e.g. denied by SELinux on some OEM
     * builds), returns a [PingResult] with `packetsSent = 0`
     * and a non-null [PingResult.errorMessage].
     */
    suspend fun pingMany(
        dest: InetAddress,
        count: Int = 3,
        intervalMs: Int = 500,
        timeoutMs: Int = 1000,
    ): PingResult = withContext(ioDispatcher) {
        require(count > 0) { "count must be positive" }
        require(timeoutMs > 0) { "timeoutMs must be positive" }
        val fd: FileDescriptor = try {
            Os.socket(OsConstants.AF_INET, OsConstants.SOCK_DGRAM, OsConstants.IPPROTO_ICMP)
        } catch (e: ErrnoException) {
            val reason = when (e.errno) {
                OsConstants.EACCES -> "permission denied (ping_group_range)"
                OsConstants.EPROTONOSUPPORT -> "kernel doesn't support unprivileged ICMP"
                else -> "socket() failed: ${e.message}"
            }
            return@withContext PingResult.fatal(reason)
        }
        try {
            if (network != null) {
                try { network.bindSocket(fd) } catch (e: Throwable) {
                    return@withContext PingResult.fatal(
                        "bindSocket failed: ${e.message}")
                }
            }
            val rtts = ArrayList<Long>(count)
            var sent = 0
            var received = 0
            // Initial identifier is a hint only — kernel rewrites.
            val baseIdent = (System.nanoTime() and 0xFFFF).toInt()
            for (seq in 0 until count) {
                if (seq > 0 && intervalMs > 0) delay(intervalMs.toLong())
                sent++
                val pkt = IcmpPacket.buildEchoRequest(
                    identifier = baseIdent,
                    sequence = seq and 0xFFFF,
                )
                val start = System.nanoTime()
                try {
                    val sentBytes = Os.sendto(
                        fd, ByteBuffer.wrap(pkt), 0, dest, 0)
                    if (sentBytes != pkt.size) {
                        Log.w(tag, "short sendto: $sentBytes/${pkt.size}")
                        continue
                    }
                } catch (e: ErrnoException) {
                    Log.w(tag, "sendto failed: ${e.message}")
                    continue
                }
                val reply = waitForReply(fd, seq, timeoutMs.toLong())
                if (reply) {
                    val rttMs = ((System.nanoTime() - start) / 1_000_000L)
                        .coerceAtLeast(0L)
                    rtts.add(rttMs)
                    received++
                }
            }
            return@withContext PingResult(sent, received, rtts, null)
        } finally {
            try { Os.close(fd) } catch (_: Throwable) {}
        }
    }

    /**
     * Wait up to [timeoutMs] for an echo reply matching [expectedSeq].
     * Returns true on match. Skips replies for other sequence
     * numbers (e.g. a stale reply from a previous send).
     */
    private fun waitForReply(
        fd: FileDescriptor,
        expectedSeq: Int,
        timeoutMs: Long,
    ): Boolean {
        val deadline = System.nanoTime() + timeoutMs * 1_000_000L
        val recvBuf = ByteArray(1024)
        while (true) {
            val remainingMs = ((deadline - System.nanoTime()) / 1_000_000L)
                .coerceAtLeast(0L)
            if (remainingMs <= 0L) return false
            val pollFd = StructPollfd().apply {
                this.fd = fd
                this.events = OsConstants.POLLIN.toShort()
            }
            val arr = arrayOf(pollFd)
            val ready = try {
                Os.poll(arr, remainingMs.toInt().coerceAtLeast(1))
            } catch (e: ErrnoException) {
                if (e.errno == OsConstants.EINTR) continue
                return false
            }
            if (ready <= 0) return false
            val bb = ByteBuffer.wrap(recvBuf)
            val n = try {
                Os.recvfrom(fd, bb, 0, null)
            } catch (e: ErrnoException) {
                Log.w(tag, "recvfrom: ${e.message}")
                return false
            }
            if (n <= 0) return false
            val parsed = IcmpPacket.parse(recvBuf, n) ?: continue
            if (!parsed.isEchoReply) {
                // Could be an error message (e.g. dest-unreachable
                // from upstream). Treat as a no-reply for this
                // sequence — the caller will time out + report
                // packet loss. Recording the error type in
                // PingResult would be nice future work.
                continue
            }
            if (parsed.sequence == (expectedSeq and 0xFFFF)) return true
            // Different sequence — could be a late reply from
            // a previous send. Keep polling until our timeout.
        }
    }
}
