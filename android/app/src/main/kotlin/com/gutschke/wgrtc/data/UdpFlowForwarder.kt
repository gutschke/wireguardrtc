package com.gutschke.wgrtc.data

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.net.DatagramPacket
import java.net.DatagramSocket

/**
 * Pump UDP datagrams between a [WgUdpFlow] (one peer-to-target tuple
 * accepted by our userspace WG endpoint) and a regular outbound
 * [DatagramSocket]. The Android app uid sends/receives via the
 * outbound socket, so the carrier sees the traffic as the phone's
 * normal UDP — same shape as Chrome's QUIC, etc.
 *
 * Three coroutines on each [forward] call:
 * - "outbound": [WgUdpFlow.receive] → [DatagramSocket.send]
 * - "inbound": [DatagramSocket.receive] → [WgUdpFlow.send]
 * - "watchdog": closes both if no traffic in [idleTtlMs]
 *
 * Returns when the flow is closed by the peer, the idle TTL fires,
 * or the calling coroutine is cancelled. Always tears down both
 * sides on the way out.
 *
 * **Idle TTL**: UDP is connectionless, so we conservatively close
 * the outbound DatagramSocket after [idleTtlMs] of silence. Default
 * 60 s matches Linux's `nf_conntrack_udp_timeout`. Going too short
 * breaks long-lived UDP services (DNS-over-UDP queries are short-
 * lived; QUIC / WebRTC keep a heartbeat); going too long leaks
 * sockets when peers disappear without telling us.
 */
class UdpFlowForwarder(
    private val idleTtlMs: Long = 60_000L,
    private val socketFactory: () -> DatagramSocket = { DatagramSocket() },
    private val maxDatagramBytes: Int = 65_535,
) {

    suspend fun forward(flow: WgUdpFlow) {
        val socket = withContext(Dispatchers.IO) {
            socketFactory().also { it.connect(flow.targetAddress) }
        }
        // Tracks last activity time (epoch ms) so the watchdog
        // can detect idle. AtomicLong because @Volatile isn't
        // applicable to local vars in Kotlin; AtomicLong gives us
        // the same memory visibility for cheap.
        val lastActivityMs = java.util.concurrent.atomic.AtomicLong(System.currentTimeMillis())
        coroutineScope {
            val outbound = launch(Dispatchers.IO) {
                while (isActive) {
                    val data = flow.receive() ?: return@launch
                    lastActivityMs.set(System.currentTimeMillis())
                    try {
                        socket.send(DatagramPacket(data, data.size,
                            flow.targetAddress))
                    } catch (_: Exception) { return@launch }
                }
            }
            val inbound = launch(Dispatchers.IO) {
                val buf = ByteArray(maxDatagramBytes)
                while (isActive) {
                    val pkt = DatagramPacket(buf, buf.size)
                    try { socket.receive(pkt) }
                    catch (_: Exception) { return@launch }
                    lastActivityMs.set(System.currentTimeMillis())
                    val copy = pkt.data.copyOfRange(0, pkt.length)
                    try { flow.send(copy) }
                    catch (_: Exception) { return@launch }
                }
            }
            val watchdog = launch {
                while (isActive) {
                    delay(WATCHDOG_TICK_MS)
                    val idle = System.currentTimeMillis() - lastActivityMs.get()
                    if (idle >= idleTtlMs) return@launch
                }
            }
            try {
                // Whichever completes first → tear down the rest.
                // Polling at the watchdog tick rate is cheap; the
                // alternative (Flow / Channel / select) is more
                // boilerplate for the same outcome.
                awaitFirstCompletion(outbound, inbound, watchdog)
            } finally {
                // Close the underlying transports so the still-
                // running pumps unblock from their JNI-level
                // socket.receive() / channel.receive() calls and
                // exit cleanly. Without this, coroutineScope
                // would deadlock awaiting children stuck in I/O.
                try { socket.close() } catch (_: Exception) {}
                try { flow.close() } catch (_: Exception) {}
                // The watchdog is NOT blocked on I/O, so closing
                // the sockets doesn't help it. Explicitly cancel
                // any survivors so coroutineScope can join them
                // and return.
                outbound.cancel()
                inbound.cancel()
                watchdog.cancel()
            }
        }
    }

    private suspend fun awaitFirstCompletion(vararg jobs: Job) {
        // Whichever finishes first triggers the cancellation of the
        // others via coroutineScope's finally. We poll because the
        // standard library's `select` would require typed
        // SelectClause0 which Job doesn't expose; the polling
        // overhead at 100ms granularity is negligible compared to
        // UDP RTTs.
        while (true) {
            if (jobs.any { it.isCompleted }) return
            delay(WATCHDOG_TICK_MS)
        }
    }

    companion object {
        private const val WATCHDOG_TICK_MS = 100L
    }
}
