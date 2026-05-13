package com.gutschke.wgrtc.data

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.channels.ClosedReceiveChannelException
import kotlinx.coroutines.launch
import java.net.InetSocketAddress
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean

/**
 * High-level facade over a [WgBridgeBackend] (= the `wgbridge.Bridge`
 * userspace WireGuard endpoint). Owned for the lifetime of one
 * host-mode tunnel.
 *
 * Responsibilities:
 * 1. Apply UAPI config (private key + peers).
 * 2. Plumb VpnService.protect() into the bridge.
 * 3. Listen on WG-side ports and feed accepted connections /
 * datagrams through the [TcpFlowForwarder] / [UdpFlowForwarder]
 * so traffic emerges from the phone's app uid ().
 * 4. Tear everything down on [close].
 *
 * (1)–(2) live here. (3) lives in the listenTcp / listenUdp methods
 * that / add.
 *
 * Threading: this class itself is not thread-safe across configure()
 * vs close() races — the caller (typically a foreground service)
 * drives lifecycle from a single supervisor coroutine. The
 * underlying [WgBridgeBackend] handles its own internal locking.
 */
class UserspaceWgEndpoint(
    private val backend: WgBridgeBackend,
) : AutoCloseable {

    private val closed = AtomicBoolean(false)

    val isClosed: Boolean get() = closed.get()

    /** Apply (or extend) the WG configuration. Same UAPI string
     * format as `wg set <iface> <args>`. */
    @Throws(Exception::class)
    fun configure(uapi: String) {
        check(!closed.get()) { "endpoint is closed" }
        backend.configureUapi(uapi)
    }

    /** Register a VpnService-backed protector — required so the
     * wire-side UDP socket bypasses any active VPN. */
    fun setProtector(protector: WgFdProtector?) {
        if (closed.get()) return
        backend.setFdProtector(protector)
    }

    /**
     * **install a catchall TCP forwarder.** Pass-through to
     * [WgBridgeBackend.installTcpCatchall]. Used by host-mode for
     * full-tunnel routing: every joiner-side TCP SYN, regardless of
     * destination port, is caught + handed to the user-supplied
     * handler which opens an outbound socket on the phone's normal
     * network. Returns the AutoCloseable that uninstalls when
     * closed.
     */
    @Throws(Exception::class)
    fun installTcpCatchall(
        handler: TcpForwarderHandler, scope: CoroutineScope,
    ): AutoCloseable {
        check(!closed.get()) { "endpoint is closed" }
        return backend.installTcpCatchall(handler, scope)
    }

    /** **install a catchall UDP forwarder.** See
     * [installTcpCatchall]. */
    @Throws(Exception::class)
    fun installUdpCatchall(
        handler: UdpForwarderHandler, scope: CoroutineScope,
    ): AutoCloseable {
        check(!closed.get()) { "endpoint is closed" }
        return backend.installUdpCatchall(handler, scope)
    }

    /** **install the through-host packet forwarder.** See
     * [WgBridgeBackend.installHostForwarder]. */
    @Throws(Exception::class)
    fun installHostForwarder(peerSubnet: String): AutoCloseable {
        check(!closed.get()) { "endpoint is closed" }
        return backend.installHostForwarder(peerSubnet)
    }


    /**
     * Start a TCP listener on the WG-side address at [port]. Each
     * accepted connection runs through:
     *
     * 1. [targetResolver]: decide the upstream destination from
     * the (peer, listen) tuple. Returns `null` to refuse —
     * the handle is closed and no forwarder runs.
     * 2. [onConnection]: usually `forwarder.forward(conn)`. Runs
     * inside [scope] so the per-connection coroutine is
     * cancellable + tied to the service lifecycle.
     *
     * The listener itself is owned by the bridge — when [close] is
     * called, the bridge tears the listener down (and any in-flight
     * [onConnection] coroutines die when [scope] is cancelled).
     *
     * Errors from [onConnection] are caught and ignored so one
     * misbehaving connection cannot cascade to the listener. The
     * caller's [scope] should have its own logging / supervisor as
     * needed.
     */
    @Throws(Exception::class)
    fun listenTcp(
        port: Int,
        scope: CoroutineScope,
        targetResolver: (peerAddr: String, listenAddr: String) -> InetSocketAddress?,
        onConnection: suspend (WgTcpConnection) -> Unit,
    ) {
        check(!closed.get()) { "endpoint is closed" }
        backend.listenTcp(port, object : WgTcpAcceptor {
            override fun onAccept(peerAddr: String, listenAddr: String, conn: WgTcpHandle) {
                val target = targetResolver(peerAddr, listenAddr)
                if (target == null) {
                    try { conn.close() } catch (_: Exception) {}
                    return
                }
                val wrapped = WgTcpHandleConnection(conn, target)
                scope.launch {
                    try {
                        onConnection(wrapped)
                    } catch (_: Exception) {
                        // One bad connection mustn't kill the listener;
                        // the forwarder already has its own teardown.
                    } finally {
                        try { wrapped.close() } catch (_: Exception) {}
                    }
                }
            }
        })
    }

    /**
     * Start a UDP listener on the WG-side address at [port]. The
     * underlying bridge delivers every inbound datagram to a single
     * receiver — we demultiplex by `peerAddr` so each unique remote
     * peer becomes one [WgUdpFlow] instance.
     *
     * Per peer:
     * 1. First datagram → resolve target; null = drop.
     * 2. Create a flow whose `receive()` drains an internal
     * [Channel] and `send()` writes back via the [WgUdpSink].
     * 3. Launch [onFlow] in [scope]. When the flow ends (peer
     * goes silent + idle TTL fires inside the forwarder, or
     * [onFlow] returns), the entry is removed from the
     * demux table.
     *
     * The internal channel is bounded ([flowChannelCapacity]).
     * Overflow drops the *new* datagram (UDP-typical behavior) so
     * a slow consumer can't back-pressure the listener thread.
     *
     * NOTE: `flow.send` is blocking from a coroutine perspective —
     * the bridge's gomobile-bound `sendTo` does the actual UDP
     * write synchronously. In practice this is microseconds.
     */
    @Throws(Exception::class)
    fun listenUdp(
        port: Int,
        scope: CoroutineScope,
        targetResolver: (peerAddr: String, listenAddr: String) -> InetSocketAddress?,
        flowChannelCapacity: Int = DEFAULT_UDP_FLOW_CAPACITY,
        onFlow: suspend (WgUdpFlow) -> Unit,
    ) {
        check(!closed.get()) { "endpoint is closed" }
        val flows = ConcurrentHashMap<String, DemuxedUdpFlow>()
        // Capture the sink we get back so flows can route replies.
        // Mutual recursion would be cleaner with a forward-decl; we
        // settle for a lateinit-style holder because the sink isn't
        // available until the listener registers.
        val sinkHolder = SinkHolder()
        val sink: WgUdpSink = backend.listenUdp(port, object : WgUdpReceiver {
            override fun onDatagram(peerAddr: String, listenAddr: String, data: ByteArray) {
                val existing = flows[peerAddr]
                if (existing != null) {
                    existing.deliver(data)
                    return
                }
                val target = targetResolver(peerAddr, listenAddr) ?: return
                val flow = DemuxedUdpFlow(
                    peerAddrStr = peerAddr,
                    listenAddrStr = listenAddr,
                    targetAddress = target,
                    sink = sinkHolder,
                    capacity = flowChannelCapacity,
                )
                // putIfAbsent keeps the very-first-datagram race
                // safe; if two threads-races see "absent" at once,
                // one wins and the loser's flow leaks one
                // datagram → recoverable since UDP is best-effort.
                val winner = flows.putIfAbsent(peerAddr, flow) ?: flow
                winner.deliver(data)
                if (winner === flow) {
                    scope.launch {
                        try {
                            onFlow(flow)
                        } catch (_: Exception) {
                            // Per-flow errors don't kill the listener.
                        } finally {
                            flows.remove(peerAddr)
                            flow.close()
                        }
                    }
                }
            }
        })
        sinkHolder.delegate = sink
    }

    /** Capture the underlying bridge's UAPI dump. Returns the
     * empty string when this endpoint has been closed — the caller
     * treats that as "no stats this tick". Pure passthrough; the
     * parsing into [UapiStats] lives in [HostModeBackend]. */
    fun snapshotUapi(): String {
        if (closed.get()) return ""
        return try { backend.snapshotUapi() } catch (_: Exception) { "" }
    }

    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        try { backend.close() } catch (_: Exception) {}
    }

    private class SinkHolder : WgUdpSink {
        @Volatile var delegate: WgUdpSink? = null
        override fun sendTo(peerAddr: String, data: ByteArray) {
            delegate?.sendTo(peerAddr, data)
                ?: throw IllegalStateException("sink not yet bound")
        }
        override fun close() { delegate?.close() }
    }

    private class DemuxedUdpFlow(
        private val peerAddrStr: String,
        @Suppress("unused") private val listenAddrStr: String,
        override val targetAddress: InetSocketAddress,
        private val sink: WgUdpSink,
        capacity: Int,
    ) : WgUdpFlow {
        override val peerAddress: InetSocketAddress = parseHostPort(peerAddrStr)
        // Channel is the inbound mailbox. DROP_OLDEST so a slow
        // consumer doesn't back-pressure (UDP-typical behavior).
        private val inbox: Channel<ByteArray> =
            Channel(capacity = capacity, onBufferOverflow = kotlinx.coroutines.channels.BufferOverflow.DROP_OLDEST)
        private val closed = AtomicBoolean(false)

        fun deliver(data: ByteArray) {
            if (!closed.get()) inbox.trySend(data)
        }

        override suspend fun receive(): ByteArray? = try {
            inbox.receive()
        } catch (_: ClosedReceiveChannelException) {
            null
        }

        override suspend fun send(data: ByteArray) {
            try { sink.sendTo(peerAddrStr, data) }
            catch (_: Exception) { /* UDP best-effort */ }
        }

        override fun close() {
            if (closed.compareAndSet(false, true)) inbox.close()
        }
    }

    companion object {
        /** Default mailbox depth per UDP flow. Sized for a typical
         * STUN/QUIC burst; if a single peer is sustained-flooding,
         * excess datagrams get DROP_OLDEST'd, matching kernel UDP
         * socket-buffer behavior. */
        const val DEFAULT_UDP_FLOW_CAPACITY: Int = 64

        /** Open a real userspace WG endpoint. Loads the JNI .so;
         * do not call from JVM unit tests. */
        @Throws(Exception::class)
        fun open(localAddr: String, mtu: Int, listenPort: Int): UserspaceWgEndpoint =
            UserspaceWgEndpoint(RealWgBridgeBackendNative.open(localAddr, mtu, listenPort))
    }
}
