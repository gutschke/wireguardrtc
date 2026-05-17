package com.gutschke.wgrtc.data

import kotlinx.coroutines.CoroutineScope

/**
 * [WgBridgeBackend] implementation built on the cgo + `//export`
 * libwgbridge_native.so. Sole production impl since dropped
 * the gomobile-bound parallel class.
 *
 * **Lifecycle.** Each instance owns a single int handle obtained
 * from [WgBridgeNative.nativeNew] / [WgBridgeNative.nativeNewWithTunFd].
 * `close()` releases the handle; subsequent calls fail with -1
 * which we silently ignore so double-close is safe.
 *
 * **TCP/UDP listeners.** Not yet implemented — production code
 * paths never call `listenTcp` / `listenUdp` (`tcpPorts =
 * emptyList()` everywhere). If a future caller does invoke them,
 * the implementation throws `UnsupportedOperationException`
 * rather than silently no-op'ing. When the listeners are
 * actually wired ( cleartext-side forwarders), we'll add
 * Go→Java callback plumbing here.
 */
class RealWgBridgeBackendNative private constructor(
    private val handle: Int,
) : WgBridgeBackend {

    @Volatile private var closed = false

    override val nativeBridgeHandle: Int get() = handle

    /** Listener IDs we own; closed in [close] so the gvisor
     * netstack's accept goroutines exit cleanly. */
    private val activeListenerIds = mutableListOf<Int>()
    private val listenersLock = Any()

    override fun configureUapi(uapi: String) {
        if (closed) throw IllegalStateException("bridge closed")
        val rc = WgBridgeNative.nativeConfigureUAPI(handle, uapi)
        check(rc == 0) {
            "nativeConfigureUAPI(handle=$handle) returned $rc — " +
                "see wgbridge_native/api.go for codes"
        }
    }

    override fun listenTcp(port: Int, acceptor: WgTcpAcceptor) {
        if (closed) throw IllegalStateException("bridge closed")
        val listenerId = WgBridgeNative.nativeListenTcp(handle, port)
        check(listenerId > 0) {
            "nativeListenTcp(handle=$handle, port=$port) returned $listenerId — " +
                "see wgbridge_native/listeners.go for codes"
        }
        TcpListenerRegistry.register(listenerId, acceptor)
        synchronized(listenersLock) { activeListenerIds += listenerId }
    }

    override fun listenUdp(port: Int, receiver: WgUdpReceiver): WgUdpSink {
        if (closed) throw IllegalStateException("bridge closed")
        val listenerId = WgBridgeNative.nativeListenUdp(handle, port)
        check(listenerId > 0) {
            "nativeListenUdp(handle=$handle, port=$port) returned $listenerId — " +
                "see wgbridge_native/listeners.go for codes"
        }
        val sink = WgUdpSinkNative(listenerId)
        UdpListenerRegistry.register(listenerId, receiver, sink)
        synchronized(listenersLock) { activeListenerIds += listenerId }
        return sink
    }

    override fun installTcpCatchall(
        handler: TcpForwarderHandler, scope: CoroutineScope,
    ): AutoCloseable {
        if (closed) throw IllegalStateException("bridge closed")
        val forwarderId = WgBridgeNative.nativeInstallTcpForwarder(handle)
        check(forwarderId > 0) {
            "nativeInstallTcpForwarder(handle=$handle) returned $forwarderId — " +
                "see wgbridge_native/listeners.go for codes"
        }
        TcpForwarderRegistry.register(forwarderId, handler, scope)
        synchronized(listenersLock) { activeListenerIds += forwarderId }
        return AutoCloseable {
            try { WgBridgeNative.nativeCloseListener(forwarderId) } catch (_: Throwable) {}
            TcpForwarderRegistry.unregister(forwarderId)
            synchronized(listenersLock) { activeListenerIds.remove(forwarderId) }
        }
    }

    override fun installUdpCatchall(
        handler: UdpForwarderHandler, scope: CoroutineScope,
    ): AutoCloseable {
        if (closed) throw IllegalStateException("bridge closed")
        val forwarderId = WgBridgeNative.nativeInstallUdpForwarder(handle)
        check(forwarderId > 0) {
            "nativeInstallUdpForwarder(handle=$handle) returned $forwarderId — " +
                "see wgbridge_native/listeners.go for codes"
        }
        UdpForwarderRegistry.register(forwarderId, handler, scope)
        synchronized(listenersLock) { activeListenerIds += forwarderId }
        return AutoCloseable {
            try { WgBridgeNative.nativeCloseListener(forwarderId) } catch (_: Throwable) {}
            UdpForwarderRegistry.unregister(forwarderId)
            synchronized(listenersLock) { activeListenerIds.remove(forwarderId) }
        }
    }

    override fun installHostForwarder(peerSubnet: String): AutoCloseable {
        if (closed) throw IllegalStateException("bridge closed")
        val forwarderId = WgBridgeNative.nativeInstallHostForwarder(handle, peerSubnet)
        check(forwarderId > 0) {
            "nativeInstallHostForwarder(handle=$handle, peerSubnet=$peerSubnet) " +
                "returned $forwarderId — see wgbridge_native/host_forwarder.go for codes"
        }
        synchronized(listenersLock) { activeListenerIds += forwarderId }
        return AutoCloseable {
            try { WgBridgeNative.nativeCloseListener(forwarderId) } catch (_: Throwable) {}
            synchronized(listenersLock) { activeListenerIds.remove(forwarderId) }
        }
    }


    override fun setFdProtector(protector: WgFdProtector?) {
        if (closed) return
        // the protect-aware Bind ON THE GO SIDE invokes
        // [WgBridgeNative.protectFd] which dispatches to whatever
        // [WgBridgeNative.installProtector] last received. The
        // bridge's bind has already opened its sockets by the time
        // we get here, so this entry point only updates the
        // protector for any FUTURE socket open — currently no path
        // re-opens the wire socket without recreating the bridge,
        // but updating is cheap and keeps the API behavior
        // intuitive ("set the latest protector").
        WgBridgeNative.installProtector(protector)
        WgBridgeNative.nativeSetFdProtector(handle)
    }

    override fun snapshotUapi(): String {
        if (closed) return ""
        return WgBridgeNative.nativeSnapshotUAPI(handle) ?: ""
    }

    override fun close() {
        if (closed) return
        closed = true
        // Close listeners FIRST so their accept / recv goroutines
        // exit before the bridge's netstack shuts down — avoids a
        // race where the goroutine sees a nil device.
        val toClose = synchronized(listenersLock) {
            val copy = activeListenerIds.toList()
            activeListenerIds.clear()
            copy
        }
        for (id in toClose) {
            try { WgBridgeNative.nativeCloseListener(id) } catch (_: Throwable) {}
            TcpListenerRegistry.unregister(id)
            UdpListenerRegistry.unregister(id)
        }
        WgBridgeNative.nativeClose(handle)
    }

    companion object {
        @Throws(Exception::class)
        fun open(localAddr: String, mtu: Int, listenPort: Int): RealWgBridgeBackendNative {
            val h = WgBridgeNative.nativeNew(localAddr, mtu, listenPort)
            check(h > 0) {
                "nativeNew($localAddr, $mtu, $listenPort) returned $h — " +
                    "see wgbridge_native/api.go for codes"
            }
            return RealWgBridgeBackendNative(h)
        }

        @Throws(Exception::class)
        fun openWithTunFd(fd: Int, mtu: Int): RealWgBridgeBackendNative {
            // mtu unused at the C side — applied via UAPI by the
            // caller. Reserved for future symmetry.
            @Suppress("UNUSED_PARAMETER") val ignored = mtu
            val h = WgBridgeNative.nativeNewWithTunFd(fd)
            check(h > 0) {
                "nativeNewWithTunFd($fd) returned $h — " +
                    "see wgbridge_native/api.go for codes"
            }
            return RealWgBridgeBackendNative(h)
        }

        fun nativeVersion(): String = WgBridgeNative.nativeVersion()
    }
}
