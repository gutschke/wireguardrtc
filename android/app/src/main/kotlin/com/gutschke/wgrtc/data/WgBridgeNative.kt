package com.gutschke.wgrtc.data

/**
 * Hand-written JNI surface for the cgo-built libwgbridge_native.so.
 * Replaces the gomobile-bind path (which triggered
 * `runtime.bulkBarrierPreWrite: unaligned arguments` on the first
 * WG handshake — archaeology); same wireguard-go internals,
 * different bridging strategy. Pattern follows wireguard-android's
 * `tools/libwg-go` — Go `//export` functions plus a thin JNI
 * wrapper in C. See `wgbridge_native/api.go` for the Go side and
 * `wgbridge_native/jni_android.c` for the C wrapper.
 *
 * Static-initialiser load: throws `UnsatisfiedLinkError` if the
 * `.so` isn't on the JNI library path (i.e. `wgbridge-native-aar`
 * not packaged correctly). Caller catches via try/catch around
 * the FIRST native call.
 */
object WgBridgeNative {

    init {
        // System.loadLibrary searches each entry of
        // ApplicationInfo.nativeLibraryDir. Our AAR's
        // `jni/<abi>/libwgbridge_native.so` lands there at
        // install time per AGP's mergeJniLibs task.
        System.loadLibrary("wgbridge_native")
    }

    /** Returns a build identifier (includes wireguard-go commit
     * for diagnostics). Round-trip works ⇒ JNI pipeline OK. */
    @JvmStatic external fun nativeVersion(): String

    /**
     * Construct a host-mode bridge with a userspace gvisor
     * netstack. Used by . Returns:
     * > 0 : opaque handle
     * < 0 : error (see api.go for codes)
     */
    @JvmStatic external fun nativeNew(localAddr: String, mtu: Int, listenPort: Int): Int

    /**
     * Open wireguard-go on an existing kernel TUN file
     * descriptor (Android `VpnService.Builder.establish()`).
     * Returns:
     * > 0 : opaque handle for the other native methods
     * -1 : invalid fd (negative)
     * -2 : CreateUnmonitoredTUNFromFD failed (SELinux /
     * ioctl rejection — see
     * memory/the dev-env README)
     * -3 : device.Up failed
     *
     * The handle takes ownership of [fd] — closing the bridge
     * (via [nativeClose]) closes the wrapped fd.
     */
    @JvmStatic external fun nativeNewWithTunFd(fd: Int): Int

    /**
     * Validate the handle for the legacy setFdProtector entry
     * point. Kept for API symmetry; the real protect plumbing
     * goes through [installProtector] + [protectFd].
     * Returns 0 on success, -1 if [handle] is unknown.
     */
    @JvmStatic external fun nativeSetFdProtector(handle: Int): Int

    /** Process-global protector callback. The protect-aware
     * `conn.Bind` on the joiner path calls [protectFd] from a
     * native thread BEFORE every UDP socket bind — that's the
     * ONLY window in which `VpnService.protect(fd)` actually
     * prevents the encrypted UDP from being captured by the
     * VPN's own AllowedIPs route.
     *
     * Set via [installProtector] before opening any joiner
     * bridge. Cleared by passing null. */
    @Volatile private var protector: WgFdProtector? = null

    /** Replace the active protect callback. Call BEFORE
     * [nativeNewWithTunFd] — the joiner Bind opens its sockets
     * inside that call. */
    @JvmStatic
    fun installProtector(p: WgFdProtector?) {
        protector = p
    }

    /** Called from the native protect-aware Bind via the
     * `wgbridge_dispatch_protect_fd` C function. Returns true
     * on protect success OR when no protector is currently
     * installed (the host-mode path + unit tests run here and
     * don't need protect — wg-go's UDP isn't captured by any
     * VpnService route). */
    @JvmStatic
    fun protectFd(fd: Int): Boolean {
        val p = protector
        if (p == null) {
            // Surface this loudly: the joiner path MUST install a
            // protector before the bridge opens. If we get here
            // from the joiner side, the order-of-operations bug
            // we thought we fixed in is back.
            android.util.Log.w("WgBridgeNative",
                "protectFd($fd) called with no protector installed " +
                "— host-mode is fine, joiner-mode is a bug")
            return true
        }
        return try {
            val ok = p.protect(fd)
            android.util.Log.i("WgBridgeNative",
                "protectFd($fd) -> $ok")
            ok
        } catch (t: Throwable) {
            android.util.Log.w("WgBridgeNative",
                "protectFd($fd) threw", t)
            false
        }
    }

    /**
     * Apply a UAPI string (see `wg(8)`'s `set` UAPI format).
     * Returns 0 on success, -1 if [handle] is unknown, -2 if
     * the IpcSet parser / peer-init failed.
     */
    @JvmStatic external fun nativeConfigureUAPI(handle: Int, uapi: String): Int

    /**
     * Snapshot wireguard-go's current state as a UAPI dump
     * (matches `wg show ... dump`). Null on error or invalid
     * handle.
     */
    @JvmStatic external fun nativeSnapshotUAPI(handle: Int): String?

    /**
     * Tear down the bridge. Idempotent — calling twice with
     * the same handle is a no-op the second time.
     */
    @JvmStatic external fun nativeClose(handle: Int)

    // ─────────────────────────────────────────────────────────
    // D4.J3 — joiner-N shared-netstack surface.
    //
    // Adapts the `wgbridgeSharedStack*` //export functions from
    // `wgbridge_native/joiner_n_exports.go`. The shared stack is
    // a separate handle namespace from the bridge handles above;
    // see `JoinerStackBackend.kt` for the high-level lifecycle.

    /**
     * Create a new shared netstack. Returns:
     *
     *   > 0 : opaque stack handle (pass to other native methods)
     *   -1  : MTU out of range (576 ≤ mtu ≤ 65535)
     *   -2  : gvisor stack init failed (out of memory or similar)
     */
    @JvmStatic external fun nativeSharedStackNew(mtu: Int): Int

    /**
     * Tear down the shared stack: stop the kernel-TUN pump (if
     * attached), close all channel endpoints, destroy the gvisor
     * stack. Idempotent.
     */
    @JvmStatic external fun nativeSharedStackClose(handle: Int)

    /**
     * Wire [fd] (typically a `VpnService.Builder.establish()` TUN
     * fd) as NIC 1 of the shared stack and start the read+write
     * pump goroutines. The shared stack TAKES OWNERSHIP of [fd];
     * the caller MUST NOT close it directly — `nativeSharedStackClose`
     * does that. Returns 0 on success, negative on error:
     *
     *   -1 : unknown stack handle
     *   -2 : attach failed (bad fd, duplicate attach, NIC create)
     */
    @JvmStatic external fun nativeSharedStackAttachKernelTun(
        handle: Int, fd: Int, mtu: Int,
    ): Int

    /**
     * Open a joiner-mode bridge as a new NIC on the shared stack
     * and program routes. Returns a BRIDGE handle (positive) —
     * pass it to `nativeConfigureUAPI` / `nativeSnapshotUAPI` /
     * `nativeClose`, exactly like a host-mode bridge.
     *
     * `peerAllowedCsv` is a comma-separated CIDR list — the
     * joiner's AllowedIPs that forward apps → this joiner. May
     * be null or empty.
     * `interfaceAddrsCsv` mirrors that shape for the reverse
     * direction (joiner → apps).
     *
     * Closing the bridge via `nativeClose` automatically detaches
     * the NIC from the shared stack.
     *
     * Returns:
     *   > 0 : bridge handle (success)
     *   -1  : unknown stack handle
     *   -2  : peer-allowed prefix parse failed
     *   -3  : interface-addr prefix parse failed
     *   -4  : openJoinerBridge failed (NIC create / wg-go Up / routes)
     */
    @JvmStatic external fun nativeSharedStackOpenJoiner(
        stackHandle: Int,
        peerAllowedCsv: String?,
        interfaceAddrsCsv: String?,
        mtu: Int,
    ): Int

    // ─────────────────────────────────────────────────────────
    // TCP / UDP listeners on the host's gvisor netstack.
    //
    // **Async model.** [nativeListenTcp] / [nativeListenUdp] are
    // synchronous — they bind the socket and start the accept /
    // recv goroutine, then return the listener handle. Each
    // accepted TCP connection fires a static callback into
    // [onTcpAccept] (below) from a JVM-attached native thread;
    // each inbound UDP datagram fires [onUdpDatagram]. Wire the
    // callback handler via [TcpListenerRegistry] / [UdpListenerRegistry].
    //
    // **Threading.** Callbacks arrive on a transient JVM thread
    // that the native side attaches per-call; they're NOT on the
    // main thread. Don't touch Compose state directly from
    // onTcpAccept / onUdpDatagram — dispatch onto your own scope.

    /**
     * Open a TCP listener on the host bridge's netstack at
     * `0.0.0.0:port`. Each accepted connection fires
     * [onTcpAccept]. Returns:
     * > 0 : listener handle (pass to [nativeCloseListener])
     * -1 : invalid bridge handle
     * -2 : bridge is not host-mode (no netstack)
     * -3 : bind failed (port collision)
     */
    @JvmStatic external fun nativeListenTcp(handle: Int, port: Int): Int

    /**
     * Open a UDP listener on the host bridge's netstack at
     * `0.0.0.0:port`. Each inbound datagram fires [onUdpDatagram].
     * Returns the listener handle (same error codes as
     * [nativeListenTcp]).
     */
    @JvmStatic external fun nativeListenUdp(handle: Int, port: Int): Int

    /**
     * Read up to `buf.size` bytes from an accepted TCP connection
     * into [buf]. Blocks until data arrives or the connection
     * closes. Returns:
     * > 0 : bytes read
     * 0 : EOF (peer closed)
     * -1 : transport error / invalid handle
     */
    @JvmStatic external fun nativeTcpRead(connHandle: Int, buf: ByteArray, bufLen: Int): Int

    /**
     * Write up to `bufLen` bytes from [buf]. Returns bytes
     * written, or -1 on error. Short writes are possible —
     * callers must loop.
     */
    @JvmStatic external fun nativeTcpWrite(connHandle: Int, buf: ByteArray, bufLen: Int): Int

    /** Close one accepted TCP connection. Idempotent. */
    @JvmStatic external fun nativeTcpClose(connHandle: Int)

    /**
     * Send a UDP datagram via [listenerHandle] to [peerAddr]
     * (in "host:port" form). Returns bytes written, or -1.
     */
    @JvmStatic external fun nativeUdpSendTo(
        listenerHandle: Int, peerAddr: String, buf: ByteArray, bufLen: Int): Int

    /** Close a TCP or UDP listener and stop its accept / recv
     * loop. Idempotent. Already-accepted TCP connections stay
     * open — close them individually via [nativeTcpClose]. */
    @JvmStatic external fun nativeCloseListener(listenerHandle: Int)

    /**
     * Dial an outbound TCP connection THROUGH the host-mode
     * bridge's netstack to `dest` (host:port). Primarily a test
     * affordance — production code generally has the host listen,
     * not dial. Returns a connection handle (use with
     * [nativeTcpRead] / [nativeTcpWrite] / [nativeTcpClose]) or
     * negative on error.
     */
    @JvmStatic external fun nativeDialTcp(handle: Int, dest: String): Int

    /**
     * Install a catchall TCP forwarder on the host bridge's
     * netstack — every inbound TCP SYN, regardless of
     * destination port, fires [onTcpForwardedAccept] with the
     * ORIGINAL DESTINATION (the address the joiner intended to
     * reach). This is the userspace-NAT path: the Kotlin
     * handler opens an outbound OS socket to the original
     * destination and pumps bytes via [TcpFlowForwarder].
     *
     * Returns:
     * > 0 : forwarder handle (close via [nativeCloseListener])
     * -1 : invalid bridge handle
     * -2 : bridge is not host-mode (no netstack)
     * -3 : netstack internal layout unexpected — see
     * `wgbridge_native/listeners.go extractStack` for the
     * reflection-based fallback that this signal
     * exposes when the upstream `golang.zx2c4.com/wireguard`
     * struct shape changes.
     */
    @JvmStatic external fun nativeInstallTcpForwarder(handle: Int): Int

    /**
     * Install a catchall UDP forwarder. Each new (peer, dest)
     * 4-tuple's first datagram fires [onUdpForwardedFlow] with a
     * fresh `flowId` plus the datagram bytes. Subsequent
     * datagrams on the same flow fire again with the *same*
     * flowId. The Kotlin handler keeps a per-flow OS
     * DatagramSocket and idle timer.
     *
     * Replies arrive on the Kotlin OS socket; they're injected
     * back into the netstack via [nativeUdpFlowWrite].
     */
    @JvmStatic external fun nativeInstallUdpForwarder(handle: Int): Int

    /**
     * Write a reply datagram back through the UDP flow's
     * netstack-side endpoint. Routes via WG to the original
     * joiner. Returns bytes written or -1.
     */
    @JvmStatic external fun nativeUdpFlowWrite(flowHandle: Int, buf: ByteArray, bufLen: Int): Int

    /** Close one UDP NAT flow. Idempotent. Used by the
     * Kotlin idle-timeout reaper. */
    @JvmStatic external fun nativeUdpFlowClose(flowHandle: Int)

    /**
     * Send an ICMPv4 echo request to [dest] (dotted IPv4) from
     * the bridge's gvisor netstack and wait up to [timeoutMs]
     * for the reply. Returns the round-trip time in
     * MICROSECONDS on success, or a negative error code (see
     * `wgbridgePingV4` in `icmp.go` for the full code table).
     *
     * Production use: diagnostic ping ("is the tunnel up?") —
     * typically from the host-mode UI pinging an enrolled joiner,
     * or from a joiner pinging the host's WG-side address to
     * verify the data path. gvisor's netstack auto-replies to
     * pings to any address it owns, so this works end-to-end
     * through WG without any host-side ICMP forwarder.
     *
     * **Limitation.** This sends the echo request via the
     * netstack's routing table — it can reach any address routed
     * out the WG tunnel (typically the host's WG-side address +
     * anything in `AllowedIPs`). It does NOT pierce out to the
     * public internet through the host (that would require a
     * Java-side ICMP forwarder). See [docs/wireguard-runtime-architecture.md §6].
     */
    @JvmStatic external fun nativePingV4(handle: Int, dest: String, timeoutMs: Int): Int

    /**
     * Install the Option B host forwarder on the bridge. Reroutes
     * gvisor's default route → virtual NIC2, enables IPv4 forwarding,
     * starts a goroutine that:
     * - Intercepts outbound ICMPv4 echoes + does real pings via
     * `golang.org/x/net/icmp`; replies are synthesised + injected
     * via `WritePackets` (bypasses gvisor's same-NIC anti-loop check).
     * - For TCP / UDP, registers the destination as a temporary
     * local address on NIC1 + re-injects the packet so the
     * existing / catchalls fire.
     *
     * [peerSubnet] (CIDR) is the WG-side subnet that stays routed
     * to NIC1; everything else goes through the forwarder. See
     * `wgbridge_native/host_forwarder.go` for the architecture +
     * error code table. Returns a listener handle (use
     * [nativeCloseListener] to uninstall) or a negative error code.
     */
    @JvmStatic external fun nativeInstallHostForwarder(handle: Int, peerSubnet: String): Int

    /**
     * Static callback fired from the native side when a TCP
     * listener accepts a new connection. The listener was
     * registered via [TcpListenerRegistry.register] when
     * `nativeListenTcp` was called; we route the accept here so
     * the per-listener [WgTcpAcceptor] callback runs.
     *
     * Called on a transient JVM-attached native thread. Keep the
     * body lean — heavy work belongs in coroutines launched from
     * the acceptor.
     */
    @JvmStatic
    fun onTcpAccept(listenerId: Int, connId: Int, peerAddr: String, listenAddr: String) {
        try {
            TcpListenerRegistry.dispatch(listenerId, connId, peerAddr, listenAddr)
        } catch (t: Throwable) {
            android.util.Log.e("WgBridgeNative",
                "onTcpAccept(listener=$listenerId, conn=$connId) threw", t)
            // Best-effort: don't leak the connection if the
            // acceptor blew up. The C-side dispatcher logs +
            // clears any pending exception.
            try { nativeTcpClose(connId) } catch (_: Throwable) {}
        }
    }

    /**
     * Static callback fired when a UDP listener receives a
     * datagram. See [onTcpAccept] for the threading rules.
     */
    @JvmStatic
    fun onUdpDatagram(listenerId: Int, peerAddr: String, listenAddr: String, data: ByteArray) {
        try {
            UdpListenerRegistry.dispatch(listenerId, peerAddr, listenAddr, data)
        } catch (t: Throwable) {
            android.util.Log.e("WgBridgeNative",
                "onUdpDatagram(listener=$listenerId, peer=$peerAddr) threw", t)
        }
    }

    /**
     * Static callback fired by the catchall TCP forwarder.
     * Unlike [onTcpAccept] (per-port listener), this carries
     * the joiner's ORIGINAL DESTINATION as `origDest` — the
     * address they were trying to reach — so the Kotlin handler
     * can open the outbound NAT socket to the right place.
     */
    @JvmStatic
    fun onTcpForwardedAccept(forwarderId: Int, connId: Int,
                              peerAddr: String, origDest: String) {
        try {
            TcpForwarderRegistry.dispatch(forwarderId, connId, peerAddr, origDest)
        } catch (t: Throwable) {
            android.util.Log.e("WgBridgeNative",
                "onTcpForwardedAccept(fwd=$forwarderId, conn=$connId) threw", t)
            try { nativeTcpClose(connId) } catch (_: Throwable) {}
        }
    }

    /**
     * Static callback fired by the catchall UDP forwarder for
     * each inbound datagram. First datagram in a flow → opens
     * the OS socket + idle timer; subsequent datagrams on the
     * same flowId → reuse the existing socket.
     */
    @JvmStatic
    fun onUdpForwardedFlow(forwarderId: Int, flowId: Int,
                            peerAddr: String, origDest: String, data: ByteArray) {
        try {
            UdpForwarderRegistry.dispatch(forwarderId, flowId, peerAddr, origDest, data)
        } catch (t: Throwable) {
            android.util.Log.e("WgBridgeNative",
                "onUdpForwardedFlow(fwd=$forwarderId, flow=$flowId) threw", t)
            try { nativeUdpFlowClose(flowId) } catch (_: Throwable) {}
        }
    }
}

