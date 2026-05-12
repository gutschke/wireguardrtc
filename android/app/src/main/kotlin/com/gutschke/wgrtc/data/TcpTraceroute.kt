package com.gutschke.wgrtc.data

import android.net.Network
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import android.system.StructPollfd
import android.util.Log
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.FileDescriptor
import java.net.InetAddress

/**
 * **Best-effort TCP traceroute for unrooted Android.**
 *
 * For each TTL from 1 to [maxHops]:
 * 1. Open a fresh TCP socket via `Os.socket`.
 * 2. Set `IP_TTL = ttl` so the SYN gets dropped (with an ICMP
 * TTL-Exceeded reply) by the router that many hops away.
 * 3. Switch to non-blocking, call `connect()` — returns
 * EINPROGRESS immediately.
 * 4. `poll()` for POLLOUT/POLLERR with the per-hop timeout.
 * 5. Read `SO_ERROR` to determine the outcome.
 *
 * Stops as soon as a hop is **reached** (connect succeeded or
 * the peer sent us a TCP RST → port closed but host is up).
 *
 * **Documented limitation: no intermediate hop IPs.**
 * Getting the actual IP address of the router that dropped each
 * SYN requires reading from the kernel's error queue
 * (`MSG_ERRQUEUE` + `SOCK_EXTENDED_ERR` ancillary data) on a
 * socket opened with `IP_RECVERR`. Android's
 * `Os.recvmsg` + `StructMsghdr` API technically exposes the
 * machinery from API 31+, but parsing the kernel's
 * `sock_extended_err` struct out of a `StructCmsghdr` blob is
 * fiddly + brittle. We deliberately stop short of that — the
 * timing pattern alone ("connect timed out at hop 4, hops 1–3
 * succeeded") localises path failures usefully without the
 * implementation complexity. A future enhancement could layer
 * MSG_ERRQUEUE parsing on top of the [HopResult] surface
 * without changing callers.
 *
 * **Egress binding.** Mirrors [IcmpPinger]: if [network] is
 * non-null, every per-hop socket is bound to that `Network`
 * so the trace follows the user's configured egress policy.
 */
class TcpTraceroute(
    private val network: Network? = null,
    private val maxHops: Int = 30,
    private val timeoutMsPerHop: Int = 1500,
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO,
    private val tag: String = "wgrtc-traceroute",
) {

    enum class HopStatus {
        /** connect() succeeded — target reached, port is open. */
        REACHED_OPEN,
        /** ECONNREFUSED — target reached, port is closed but host responded with RST. */
        REACHED_CLOSED,
        /** poll() timed out — hop dropped silently or path is broken. */
        TIMEOUT,
        /** EHOSTUNREACH / ENETUNREACH — kernel observed an ICMP unreachable. */
        UNREACHABLE,
        /** Other errno from socket/setsockopt/connect/getsockopt. */
        ERROR,
    }

    data class HopResult(
        val ttl: Int,
        val status: HopStatus,
        /** Wall-clock RTT in ms. Null when poll timed out. */
        val rttMs: Long?,
        /** Intermediate hop IP (always null in this MVP impl — see kdoc). */
        val hopAddress: InetAddress? = null,
        val errorMessage: String? = null,
    ) {
        val isFinalHop: Boolean get() =
            status == HopStatus.REACHED_OPEN || status == HopStatus.REACHED_CLOSED
    }

    /** Run a complete trace. Returns hops in TTL order. */
    suspend fun trace(target: InetAddress, port: Int = 80): List<HopResult> =
        withContext(ioDispatcher) {
            val hops = ArrayList<HopResult>(maxHops)
            for (ttl in 1..maxHops) {
                val h = traceOne(target, port, ttl)
                hops += h
                if (h.isFinalHop) break
            }
            hops
        }

    /**
     * Streaming variant: invokes [onHop] for each hop as soon as
     * it's measured. Useful for the UI so the user sees results
     * land in real time rather than waiting for the full trace.
     * Returns the complete list at the end (same contents as
     * what [onHop] was called with).
     */
    suspend fun traceStreaming(
        target: InetAddress,
        port: Int = 80,
        onHop: suspend (HopResult) -> Unit,
    ): List<HopResult> = withContext(ioDispatcher) {
        val hops = ArrayList<HopResult>(maxHops)
        for (ttl in 1..maxHops) {
            val h = traceOne(target, port, ttl)
            hops += h
            onHop(h)
            if (h.isFinalHop) break
        }
        hops
    }

    private fun traceOne(target: InetAddress, port: Int, ttl: Int): HopResult {
        val fd: FileDescriptor = try {
            Os.socket(OsConstants.AF_INET, OsConstants.SOCK_STREAM,
                OsConstants.IPPROTO_TCP)
        } catch (e: ErrnoException) {
            return HopResult(ttl, HopStatus.ERROR, null,
                errorMessage = "socket: ${e.message}")
        }
        try {
            if (network != null) {
                try { network.bindSocket(fd) } catch (e: Throwable) {
                    return HopResult(ttl, HopStatus.ERROR, null,
                        errorMessage = "bindSocket: ${e.message}")
                }
            }
            try {
                Os.setsockoptInt(fd, OsConstants.IPPROTO_IP,
                    OsConstants.IP_TTL, ttl)
            } catch (e: ErrnoException) {
                return HopResult(ttl, HopStatus.ERROR, null,
                    errorMessage = "setsockoptInt(IP_TTL): ${e.message}")
            }
            // Non-blocking so we control the timeout via poll.
            try {
                val flags = Os.fcntlInt(fd, OsConstants.F_GETFL, 0)
                Os.fcntlInt(fd, OsConstants.F_SETFL, flags or OsConstants.O_NONBLOCK)
            } catch (e: ErrnoException) {
                return HopResult(ttl, HopStatus.ERROR, null,
                    errorMessage = "fcntl(O_NONBLOCK): ${e.message}")
            }
            val start = System.nanoTime()
            try {
                Os.connect(fd, target, port)
                // Synchronous connect — only happens for unusual
                // local routes; counts as reaching the destination.
                return HopResult(ttl, HopStatus.REACHED_OPEN,
                    elapsedMs(start), errorMessage = null)
            } catch (e: ErrnoException) {
                if (e.errno != OsConstants.EINPROGRESS) {
                    return HopResult(ttl, statusFromErrno(e.errno),
                        elapsedMs(start), errorMessage = e.message)
                }
                // Fall through: poll for completion.
            }
            val pollFd = StructPollfd().apply {
                this.fd = fd
                this.events =
                    (OsConstants.POLLOUT or OsConstants.POLLERR).toShort()
            }
            val ready = try {
                Os.poll(arrayOf(pollFd), timeoutMsPerHop)
            } catch (e: ErrnoException) {
                return HopResult(ttl, HopStatus.ERROR, elapsedMs(start),
                    errorMessage = "poll: ${e.message}")
            }
            if (ready <= 0) {
                return HopResult(ttl, HopStatus.TIMEOUT, null)
            }
            val rttMs = elapsedMs(start)
            // To read the async connect()'s outcome, call connect()
            // again on the same fd. Linux returns:
            // - success (no throw) if the connect just-completed
            // - EISCONN if it had already completed (POLLOUT
            // was set because of writable state)
            // - the actual errno of the failed connect otherwise
            // This sidesteps the lack of `Os.getsockoptInt` on
            // Android's public API surface.
            return try {
                Os.connect(fd, target, port)
                HopResult(ttl, HopStatus.REACHED_OPEN, rttMs)
            } catch (e: ErrnoException) {
                when (e.errno) {
                    OsConstants.EISCONN -> HopResult(ttl,
                        HopStatus.REACHED_OPEN, rttMs)
                    OsConstants.ECONNREFUSED -> HopResult(ttl,
                        HopStatus.REACHED_CLOSED, rttMs)
                    OsConstants.EHOSTUNREACH,
                    OsConstants.ENETUNREACH -> HopResult(ttl,
                        HopStatus.UNREACHABLE, rttMs,
                        errorMessage = e.message)
                    OsConstants.ETIMEDOUT -> HopResult(ttl,
                        HopStatus.TIMEOUT, rttMs,
                        errorMessage = e.message)
                    else -> HopResult(ttl, HopStatus.ERROR, rttMs,
                        errorMessage = e.message)
                }
            }
        } finally {
            try { Os.close(fd) } catch (_: Throwable) {}
        }
    }

    private fun statusFromErrno(errno: Int): HopStatus = when (errno) {
        OsConstants.ECONNREFUSED -> HopStatus.REACHED_CLOSED
        OsConstants.EHOSTUNREACH, OsConstants.ENETUNREACH -> HopStatus.UNREACHABLE
        OsConstants.ETIMEDOUT -> HopStatus.TIMEOUT
        else -> HopStatus.ERROR
    }

    private fun elapsedMs(startNanos: Long): Long =
        ((System.nanoTime() - startNanos) / 1_000_000L).coerceAtLeast(0L)
}
