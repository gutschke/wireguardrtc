package com.gutschke.wgrtc.data

import android.util.Log
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.util.concurrent.ConcurrentHashMap

/**
 * **UDP catchall forwarder handler.**
 *
 * One handler instance per host bridge; it processes every UDP
 * datagram the netstack catchall forwarder caught. Per-flow
 * (peer, dest) state lives in [flows]: the first datagram in a
 * new flow opens an OS-side [UdpEgress] (a `DatagramSocket`-shaped
 * abstraction, behind the [UdpEgressFactory] seam for testability)
 * and starts a reply-reader coroutine; subsequent datagrams on
 * the same flow re-use the open egress.
 *
 * **DNS dispatch.** When a [dnsProxy] is supplied AND the flow's
 * destination port equals 53, the handler bypasses the OS socket
 * entirely and hands the query to the proxy. The proxy's
 * response is injected back into the netstack via the
 * [replyInjector] callback (which production wires to
 * [WgBridgeNative.nativeUdpFlowWrite]). Reason: the joiner's
 * DNS query should NOT egress out the cellular interface and
 * leak query content; we resolve through the phone's normal
 * resolver chain (which may be DoH, may be private DNS, etc.).
 *
 * **Idle timeout.** Each flow has an idle timer; if no traffic
 * passes through it for [idleTimeoutMs], the flow is closed
 * (both the netstack-side endpoint via [WgBridgeNative.nativeUdpFlowClose]
 * and the OS-side socket). Standard NAT box behavior.
 */
class UdpForwarderHandler(
    private val egressFactory: UdpEgressFactory =
        DatagramSocketUdpEgressFactory(),
    private val targetResolver: (peer: String, origDest: String) -> InetSocketAddress?,
    /** Optional DNS proxy. When non-null, port-53 flows route
     * through it instead of opening an OS socket. */
    private val dnsProxy: DnsProxy? = null,
    /** Callback that injects a reply datagram into the netstack
     * toward the joiner. Production wires this to
     * `nativeUdpFlowWrite(flowId, bytes, len)`. */
    private val replyInjector: (flowId: Int, bytes: ByteArray) -> Unit = { id, b ->
        WgBridgeNative.nativeUdpFlowWrite(id, b, b.size)
    },
    /** Callback fired when a flow ends (idle reap or error). */
    private val onFlowClose: (flowId: Int, peer: String) -> Unit = { _, _ -> },
    /** Idle timeout per flow. 30 s matches typical NAT boxes. */
    private val idleTimeoutMs: Long = 30_000L,
    /** Receive-poll interval inside the reader coroutine.
     * Smaller = lower reply latency, larger = less CPU.
     * 100 ms balances both for typical request/reply UDP. */
    private val replyPollMs: Int = 100,
    /** Dispatcher for the blocking socket I/O. Defaults to
     * `Dispatchers.IO`; tests inject the test scheduler so
     * `advanceUntilIdle()` is reliable. */
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO,
    /** Whether to start the per-flow reply-reader coroutine.
     * Production always wants this (true). Unit tests that
     * exercise dispatch logic without real sockets pass false
     * to avoid the polling loop deadlocking against virtual
     * time. The e2e instrumented test covers the reader path
     * with a real `DatagramSocket`. */
    private val startReaders: Boolean = true,
    /** Time source. Default = wall clock. Tests inject the
     * coroutines `testScheduler.currentTime` so the idle-reaper
     * test plays nicely with virtual time advancement. */
    private val nowMsProvider: () -> Long = { System.currentTimeMillis() },
    private val tag: String = "wgrtc-fwd-udp",
) {
    private data class FlowState(
        val flowId: Int,
        val peer: String,
        val egress: UdpEgress,
        val target: InetSocketAddress,
        var lastActivity: Long,
        val readerJob: Job,
    )

    private val flows = ConcurrentHashMap<Int, FlowState>()

    /**
     * Process one inbound datagram. Returns immediately; the
     * actual socket I/O runs on [scope].
     */
    fun dispatch(
        scope: CoroutineScope,
        flowId: Int,
        peerAddr: String,
        origDest: String,
        payload: ByteArray,
    ) {
        // Fast path: existing flow → reuse its open egress.
        val existing = flows[flowId]
        if (existing != null) {
            existing.lastActivity = nowMs()
            scope.launch(ioDispatcher) {
                try { existing.egress.send(existing.target, payload) }
                catch (t: Throwable) {
                    Log.w(tag, "egress send failed for flow=$flowId: ${t.message}")
                    closeFlow(flowId)
                }
            }
            return
        }
        val parsed = parseHostPort(origDest)
        if (parsed == null) {
            Log.w(tag, "malformed origDest=$origDest from $peerAddr; closing flow")
            closeNativeFlow(flowId)
            onFlowClose(flowId, peerAddr)
            return
        }
        // DNS short-circuit.
        if (dnsProxy != null && parsed.port == 53) {
            scope.launch(ioDispatcher) {
                val reply = try { dnsProxy.handle(payload) } catch (_: Throwable) { null }
                if (reply != null) {
                    try { replyInjector(flowId, reply) }
                    catch (t: Throwable) {
                        Log.w(tag, "DNS reply inject failed: ${t.message}")
                    }
                }
                closeNativeFlow(flowId)
                onFlowClose(flowId, peerAddr)
            }
            return
        }
        val target = targetResolver(peerAddr, origDest)
        if (target == null) {
            Log.i(tag, "resolver refused $peerAddr → $origDest")
            closeNativeFlow(flowId)
            onFlowClose(flowId, peerAddr)
            return
        }
        // Open the egress synchronously. `DatagramSocket` ctor
        // does an ephemeral-port bind (no network I/O), and UDP
        // `send` is fire-and-forget at the kernel level. Doing
        // both here (rather than inside `scope.launch`) means
        // the next `dispatch()` call for the same flowId
        // immediately sees the state, regardless of how the
        // calling scope's dispatcher chooses to schedule
        // launches.
        Log.i(tag, "flow=$flowId $peerAddr → $origDest first datagram ${payload.size}B; opening egress to $target")
        val egress: UdpEgress = try { egressFactory.open(target) }
            catch (t: Throwable) {
                Log.w(tag, "open egress to $target failed: ${t.message}")
                closeNativeFlow(flowId)
                onFlowClose(flowId, peerAddr)
                return
            }
        try { egress.send(target, payload) }
        catch (t: Throwable) {
            Log.w(tag, "first send to $target failed: ${t.message}")
            try { egress.close() } catch (_: Throwable) {}
            closeNativeFlow(flowId)
            onFlowClose(flowId, peerAddr)
            return
        }
        val readerJob = if (startReaders) {
            scope.launch(ioDispatcher) { replyReaderLoop(flowId, peerAddr, egress) }
        } else Job()
        val state = FlowState(
            flowId = flowId,
            peer = peerAddr,
            egress = egress,
            target = target,
            lastActivity = nowMs(),
            readerJob = readerJob,
        )
        flows[flowId] = state
        scope.launch(ioDispatcher) { idleReaperLoop(flowId) }
    }

    /** Wrapped JNI flow-close so JVM unit tests don't trip on
     * `WgBridgeNative`'s class init (the static init calls
     * System.loadLibrary which fails on plain JVM). */
    private fun closeNativeFlow(flowId: Int) {
        try { WgBridgeNative.nativeUdpFlowClose(flowId) }
        catch (_: Throwable) { /* ok in tests */ }
    }

    private suspend fun replyReaderLoop(flowId: Int, peer: String, egress: UdpEgress) {
        while (true) {
            val state = flows[flowId] ?: return
            val reply: ByteArray? = try { egress.receive(replyPollMs) }
                catch (_: Throwable) { null }
            if (reply == null) {
                // Either the socket closed or no reply arrived this
                // tick. Yield + back off so we don't busy-loop if
                // the egress's receive happens to return null
                // immediately (real DatagramSocket honors the
                // timeout, but fakes + an empty queue can short-
                // circuit). delay() is a suspension point so the
                // coroutine scheduler can also cancel us.
                if (!flows.containsKey(flowId)) return
                delay(replyPollMs.toLong())
                continue
            }
            state.lastActivity = nowMs()
            try { replyInjector(flowId, reply) }
            catch (t: Throwable) {
                Log.w(tag, "inject reply for flow=$flowId failed: ${t.message}")
                closeFlow(flowId)
                return
            }
        }
    }

    private suspend fun idleReaperLoop(flowId: Int) {
        while (true) {
            delay(idleTimeoutMs / 2)
            val state = flows[flowId] ?: return
            val idle = nowMs() - state.lastActivity
            if (idle >= idleTimeoutMs) {
                Log.i(tag, "flow=$flowId idle ${idle}ms; closing")
                closeFlow(flowId)
                return
            }
        }
    }

    private fun closeFlow(flowId: Int) {
        val state = flows.remove(flowId) ?: return
        try { state.egress.close() } catch (_: Throwable) {}
        try { state.readerJob.cancel() } catch (_: Throwable) {}
        closeNativeFlow(flowId)
        onFlowClose(flowId, state.peer)
    }

    private fun nowMs(): Long = nowMsProvider()

    private fun parseHostPort(s: String): InetSocketAddress? {
        val colon = s.lastIndexOf(':')
        if (colon <= 0 || colon == s.length - 1) return null
        val host = s.substring(0, colon).trim().trim('[', ']')
        val port = s.substring(colon + 1).trim().toIntOrNull() ?: return null
        if (port !in 1..65535) return null
        return try { InetSocketAddress(host, port) } catch (_: Throwable) { null }
    }
}

/**
 * Outbound UDP egress abstraction. Production = a
 * `java.net.DatagramSocket`; tests inject a fake. Pulled out as
 * an interface so [UdpForwarderHandler] can be unit-tested
 * without real sockets.
 */
interface UdpEgress {
    /** Send `data` to `target`. Throws on I/O error. */
    @Throws(IOException::class)
    fun send(target: InetSocketAddress, data: ByteArray)

    /** Block (up to `timeoutMs` ms) for an inbound reply.
     * Returns the datagram bytes, null on timeout (more reads
     * may yield data later), or throws on close. The
     * throw-on-close contract matters for the reply-reader loop
     * — null means "wait some more"; thrown means "give up." */
    @Throws(IOException::class)
    fun receive(timeoutMs: Int): ByteArray?

    /** Idempotent close. Subsequent [receive] calls throw. */
    fun close()
}

/** Factory for [UdpEgress] — one per (peer, dest) flow. */
fun interface UdpEgressFactory {
    fun open(target: InetSocketAddress): UdpEgress
}

/** Production factory: real OS `DatagramSocket`. The optional
 * [socketProvider] lets [EgressSelector] supply a pre-bound
 * socket (e.g. bound to a specific [android.net.Network] for
 * Wi-Fi-only egress); when not supplied, the kernel picks an
 * ephemeral port on the default route. */
class DatagramSocketUdpEgressFactory(
    private val bufferSize: Int = 64 * 1024,
    private val socketProvider: () -> DatagramSocket = ::DatagramSocket,
) : UdpEgressFactory {
    override fun open(target: InetSocketAddress): UdpEgress =
        DatagramSocketUdpEgress(socketProvider(), bufferSize)
}

private class DatagramSocketUdpEgress(
    private val socket: DatagramSocket,
    private val bufferSize: Int,
) : UdpEgress {
    private val recvBuf = ByteArray(bufferSize)

    override fun send(target: InetSocketAddress, data: ByteArray) {
        socket.send(DatagramPacket(data, data.size, target))
    }

    override fun receive(timeoutMs: Int): ByteArray? {
        socket.soTimeout = timeoutMs
        return try {
            val pkt = DatagramPacket(recvBuf, recvBuf.size)
            socket.receive(pkt)
            recvBuf.copyOfRange(0, pkt.length)
        } catch (_: java.net.SocketTimeoutException) {
            null
        } catch (_: java.net.SocketException) {
            null
        }
    }

    override fun close() {
        try { socket.close() } catch (_: Throwable) {}
    }
}

/** Routes [WgBridgeNative.onUdpForwardedFlow] callbacks to the
 * per-bridge [UdpForwarderHandler]. */
object UdpForwarderRegistry {
    private val handlers = ConcurrentHashMap<Int, Entry>()
    private data class Entry(
        val handler: UdpForwarderHandler,
        val scope: CoroutineScope,
    )

    fun register(forwarderId: Int, handler: UdpForwarderHandler,
                 scope: CoroutineScope) {
        handlers[forwarderId] = Entry(handler, scope)
    }

    fun unregister(forwarderId: Int) { handlers.remove(forwarderId) }

    fun dispatch(forwarderId: Int, flowId: Int,
                 peerAddr: String, origDest: String, data: ByteArray) {
        val entry = handlers[forwarderId]
        if (entry == null) {
            try { WgBridgeNative.nativeUdpFlowClose(flowId) } catch (_: Throwable) {}
            return
        }
        entry.handler.dispatch(entry.scope, flowId, peerAddr, origDest, data)
    }
}
