package com.gutschke.wgrtc.data

import kotlinx.coroutines.CoroutineScope

/**
 * Abstraction over `libwgbridge_native.so` (cgo + //export build
 * of wireguard-go). The production implementation
 * ([RealWgBridgeBackendNative]) wraps the JNI surface 1:1; tests
 * substitute a fake so the rest of the plumbing can be
 * exercised on a plain JVM without the .so.
 *
 * Mirrors the Go-side //export functions exactly — see
 * `android/wgbridge_native/api.go` for the source-of-truth doc
 * on each method's semantics.
 */
interface WgBridgeBackend : AutoCloseable {

    /** Native handle that identifies this bridge in the wgbridge
     *  registry — needed by CASCADE-2 to wire the host-mode
     *  bridge into the cross-stack ferry.  Returns 0 for backends
     *  (test fakes) that don't bind to a native bridge. */
    val nativeBridgeHandle: Int get() = 0

    /** Apply a wireguard-tools UAPI string ("private_key=... \npeer ...").
     * Throws on parse failure or wrong-state device. */
    @Throws(Exception::class)
    fun configureUapi(uapi: String)

    /** Listen on `port` (WG-side address). Each accepted TCP
     * connection fires [WgTcpAcceptor.onAccept] on a fresh thread. */
    @Throws(Exception::class)
    fun listenTcp(port: Int, acceptor: WgTcpAcceptor)

    /** Listen on `port` (WG-side address). Each inbound datagram
     * fires [WgUdpReceiver.onDatagram]. Returned [WgUdpSink] is
     * used for outbound replies. */
    @Throws(Exception::class)
    fun listenUdp(port: Int, receiver: WgUdpReceiver): WgUdpSink

    /**
     * **install a catchall TCP forwarder.** Replaces gvisor's
     * default TCP protocol handler with one that catches every
     * inbound SYN regardless of destination port. Each accepted
     * connection fires [TcpForwarderHandler] with the joiner's
     * peer address + the *original destination* they were trying
     * to reach.
     *
     * Mutually exclusive with [listenTcp] — installing the
     * catchall sinks the netstack's default TCP handler, which
     * means port-specific listeners stop receiving. Pick one
     * model per bridge.
     *
     * Returns an [AutoCloseable] whose close() tears down the
     * forwarder + unregisters the handler. Default impl throws —
     * test fakes only need to override when they exercise the
     * catchall path.
     */
    @Throws(Exception::class)
    fun installTcpCatchall(
        handler: TcpForwarderHandler,
        scope: CoroutineScope,
    ): AutoCloseable =
        throw UnsupportedOperationException("installTcpCatchall not supported by this backend")

    /**
     * **install a catchall UDP forwarder.** Same shape as
     * [installTcpCatchall] for UDP: each new (peer, dest) flow
     * fires [UdpForwarderHandler], with first-datagram payload.
     */
    @Throws(Exception::class)
    fun installUdpCatchall(
        handler: UdpForwarderHandler,
        scope: CoroutineScope,
    ): AutoCloseable =
        throw UnsupportedOperationException("installUdpCatchall not supported by this backend")

    /**
     * **install the through-host packet forwarder.** Adds a
     * virtual NIC2 to the bridge's netstack, moves the default
     * route to it, and starts a goroutine that bridges non-local
     * destination traffic via the host's real network:
     * - ICMP via real `golang.org/x/net/icmp` ping + synthesised
     * reply
     * - TCP / UDP via the temp-local-address re-injection trick,
     * so the existing TCP/UDP catchalls handle the OS-socket NAT
     *
     * [peerSubnet] (CIDR, e.g. "10.99.0.0/24") is the WG-side
     * subnet that stays routed to NIC1 (host + joiners reachable
     * directly); everything else routes through the forwarder.
     *
     * Mutually compatible with [installTcpCatchall] /
     * [installUdpCatchall] — and in fact *requires* them for TCP
     * and UDP to actually exit the phone. Without the catchalls
     * the re-injected packets are dropped (no transport handler).
     */
    @Throws(Exception::class)
    fun installHostForwarder(peerSubnet: String): AutoCloseable =
        throw UnsupportedOperationException("installHostForwarder not supported by this backend")


    /** Register the VpnService.protect() hook; the bridge calls
     * [WgFdProtector.protect] before bind() on every wire-side UDP
     * socket so the encrypted-outer traffic bypasses any active
     * VPN. Pass `null` to clear. */
    fun setFdProtector(protector: WgFdProtector?)

    /** Tear down the bridge: stops listeners, closes the WG device,
     * releases the netstack stack. Idempotent. */
    override fun close()

    /**
     * Return wireguard-go's current state as a UAPI dump (the same
     * format `wg show ... dump` emits). Used by the host-mode UI to
     * surface per-peer rx/tx + last-handshake without having to keep
     * its own counters. Returns the empty string when the bridge is
     * closed; otherwise the underlying error is thrown.
     *
     * Default returns `""` so existing fakes don't have to override
     * — only the production [RealWgBridgeBackendNative] and tests
     * that specifically exercise stats need a real implementation.
     */
    @Throws(Exception::class)
    fun snapshotUapi(): String = ""
}

/** Per-accepted-TCP-connection callback. Called once per accept. */
interface WgTcpAcceptor {
    fun onAccept(peerAddr: String, listenAddr: String, conn: WgTcpHandle)
}

/** Per-datagram callback. */
interface WgUdpReceiver {
    fun onDatagram(peerAddr: String, listenAddr: String, data: ByteArray)
}

/** Outbound UDP — write a datagram back over the WG tunnel. */
interface WgUdpSink {
    @Throws(Exception::class)
    fun sendTo(peerAddr: String, data: ByteArray)
    fun close()
}

/** Wraps `VpnService.protect(int)`. Returns true on success. */
fun interface WgFdProtector {
    fun protect(fd: Int): Boolean
}

/**
 * One accepted TCP connection on the WG side. Read returns -1
 * at EOF (callers don't have to catch a Go-EOF exception);
 * throws only on genuine errors (the underlying netstack TCP
 * failed, e.g. peer reset).
 */
interface WgTcpHandle {
    val peerAddress: String
    val listenAddress: String

    /** Reads up to `buf.size` bytes. Returns the number read, or
     * -1 at EOF. Throws on transport error. */
    @Throws(Exception::class)
    fun read(buf: ByteArray): Int

    /** Writes the full slice. */
    @Throws(Exception::class)
    fun write(buf: ByteArray)

    fun close()
}
