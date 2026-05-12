package com.gutschke.wgrtc.data

import java.util.concurrent.ConcurrentHashMap

/**
 * Routes native TCP-accept callbacks to per-listener Kotlin
 * acceptors. The native side has a single static dispatch entry
 * point ([WgBridgeNative.onTcpAccept]); per-listener routing
 * lives here in Kotlin so the JNI surface stays small.
 *
 * Lifetime contract:
 * * [register] is called from the same code path that invokes
 * [WgBridgeNative.nativeListenTcp]. Pass the returned
 * listener id.
 * * [unregister] runs on close. After unregister, any in-flight
 * accept callback for that id is silently dropped (the
 * connection is closed by [WgBridgeNative.onTcpAccept]'s error
 * handler).
 */
object TcpListenerRegistry {
    private val acceptors = ConcurrentHashMap<Int, WgTcpAcceptor>()

    fun register(listenerId: Int, acceptor: WgTcpAcceptor) {
        acceptors[listenerId] = acceptor
    }

    fun unregister(listenerId: Int) {
        acceptors.remove(listenerId)
    }

    /** Called from the native callback dispatcher. No-op if the
     * listener was unregistered between accept and dispatch. */
    fun dispatch(listenerId: Int, connId: Int, peerAddr: String, listenAddr: String) {
        val acceptor = acceptors[listenerId]
        if (acceptor == null) {
            // Listener was closed between the C-side accept and
            // this dispatch. Tear the connection down so the
            // peer sees a clean close.
            try { WgBridgeNative.nativeTcpClose(connId) } catch (_: Throwable) {}
            return
        }
        val conn = WgTcpHandleNative(connId, peerAddr, listenAddr)
        acceptor.onAccept(peerAddr, listenAddr, conn)
    }
}

/**
 * Routes catchall-TCP-forwarder accepts (from
 * [WgBridgeNative.onTcpForwardedAccept]) to the
 * [TcpForwarderHandler] registered for the forwarder. Each
 * accept carries the joiner's **original destination** instead
 * of a bound listener address — that's the load-bearing
 * difference from [TcpListenerRegistry].
 *
 * Lifetime: register when `nativeInstallTcpForwarder` returned
 * a handle; unregister on bridge close. Late-arriving accepts
 * (handler gone between gvisor's accept + dispatch) close the
 * connection silently.
 */
object TcpForwarderRegistry {
    private val handlers = java.util.concurrent.ConcurrentHashMap<Int, ForwarderEntry>()

    /** Stored together so [dispatch] can hand the handler a
     * ready-made [WgTcpHandle] without an extra lookup. */
    private data class ForwarderEntry(
        val handler: TcpForwarderHandler,
        val scope: kotlinx.coroutines.CoroutineScope,
    )

    fun register(forwarderId: Int, handler: TcpForwarderHandler,
                 scope: kotlinx.coroutines.CoroutineScope) {
        handlers[forwarderId] = ForwarderEntry(handler, scope)
    }

    fun unregister(forwarderId: Int) {
        handlers.remove(forwarderId)
    }

    fun dispatch(forwarderId: Int, connId: Int, peerAddr: String, origDest: String) {
        val entry = handlers[forwarderId]
        if (entry == null) {
            try { WgBridgeNative.nativeTcpClose(connId) } catch (_: Throwable) {}
            return
        }
        val wg = WgTcpHandleNative(connId, peerAddr, origDest)
        entry.handler.dispatch(entry.scope, peerAddr, origDest, wg)
    }
}

/** Mirror of [TcpListenerRegistry] for UDP datagrams. */
object UdpListenerRegistry {
    private val receivers = ConcurrentHashMap<Int, ListenerEntry>()

    /** Stored together so [dispatch] can hand the receiver a
     * ready-made [WgUdpSink] that targets the same listener
     * without an extra lookup per datagram. */
    private data class ListenerEntry(val receiver: WgUdpReceiver, val sink: WgUdpSink)

    fun register(listenerId: Int, receiver: WgUdpReceiver, sink: WgUdpSink) {
        receivers[listenerId] = ListenerEntry(receiver, sink)
    }

    fun unregister(listenerId: Int) {
        receivers.remove(listenerId)
    }

    fun dispatch(listenerId: Int, peerAddr: String, listenAddr: String, data: ByteArray) {
        val entry = receivers[listenerId] ?: return
        entry.receiver.onDatagram(peerAddr, listenAddr, data)
    }
}

/**
 * [WgTcpHandle] backed by a native connection ID. Read / write
 * are blocking — call them from an IO-dispatched coroutine, not
 * the main thread. Closing is idempotent and tells the native
 * side to release the connection.
 */
internal class WgTcpHandleNative(
    val connId: Int,
    override val peerAddress: String,
    override val listenAddress: String,
) : WgTcpHandle {
    @Volatile private var closed = false

    override fun read(buf: ByteArray): Int {
        if (closed) return -1
        return WgBridgeNative.nativeTcpRead(connId, buf, buf.size)
    }

    override fun write(buf: ByteArray) {
        if (closed) throw java.io.IOException("connection closed")
        var written = 0
        while (written < buf.size) {
            // Native call writes from offset 0. For partial
            // writes we'd need to slice, but in practice gonet
            // TCP writes the full buffer in one call for small
            // payloads (the test path). Fall back to a slice
            // copy when a short write happens.
            val toWrite = buf.size - written
            val slice = if (written == 0) buf else buf.copyOfRange(written, buf.size)
            val n = WgBridgeNative.nativeTcpWrite(connId, slice, toWrite)
            if (n < 0) throw java.io.IOException(
                "nativeTcpWrite failed (rc=$n) after $written of ${buf.size} bytes")
            if (n == 0) {
                // Per the gonet contract this shouldn't happen on
                // a healthy connection, but defensively bail out
                // rather than spin.
                throw java.io.IOException("zero-byte write on connection $connId")
            }
            written += n
        }
    }

    override fun close() {
        if (closed) return
        closed = true
        try { WgBridgeNative.nativeTcpClose(connId) } catch (_: Throwable) {}
    }
}

/**
 * [WgUdpSink] backed by a native listener ID. Outbound datagrams
 * go via [WgBridgeNative.nativeUdpSendTo]. Closing this sink does
 * NOT close the underlying listener — that's the caller's job via
 * [WgBridgeNative.nativeCloseListener] (or
 * [RealWgBridgeBackendNative.close]).
 */
internal class WgUdpSinkNative(
    val listenerId: Int,
) : WgUdpSink {
    @Volatile private var closed = false

    override fun sendTo(peerAddr: String, data: ByteArray) {
        if (closed) throw java.io.IOException("sink closed")
        val n = WgBridgeNative.nativeUdpSendTo(listenerId, peerAddr, data, data.size)
        if (n < 0) throw java.io.IOException(
            "nativeUdpSendTo(listener=$listenerId, peer=$peerAddr) failed (rc=$n)")
    }

    override fun close() {
        closed = true
        // Listener close lives with the bridge; this sink is just
        // a writer view of it.
    }
}
