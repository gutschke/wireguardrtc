package com.gutschke.wgrtc.data

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import java.net.InetSocketAddress
import java.util.concurrent.atomic.AtomicBoolean

/**
 * host-mode runner: composes a [UserspaceWgEndpoint] with
 * the per-protocol forwarders ([TcpFlowForwarder], [UdpFlowForwarder])
 * to implement "phone hosts the WG endpoint and re-emits
 * decrypted traffic via app-uid sockets so the carrier sees normal
 * phone traffic".
 *
 * One [HostModeRunner] per HOST_MODE tunnel. The caller (typically
 * the [com.gutschke.wgrtc.OfferListenerService]) constructs the
 * runner with an injected [WgBridgeBackendFactory] and a
 * resource-bound [parentScope], then calls [start] / [stop] in
 * lifecycle response.
 *
 * **Listen-port model (PoC).** The current wgbridge `ListenTCP` /
 * `ListenUDP` API binds a netstack listener on one port at a time;
 * 's "catch every dst port" semantics need a transparent
 * forwarder built on netstack's `tcp.NewForwarder`, which the
 * gomobile binding doesn't expose. As a PoC we listen on the set
 * the caller declares ([HostModeRunnerConfig.tcpPorts] /
 * [HostModeRunnerConfig.udpPorts]). Hotspot-share use cases
 * typically only need TCP/80, TCP/443, UDP/53 — those land in the
 * default; richer port sets ride on a wgbridge upgrade tracked
 * separately.
 *
 * **Concurrency.** All listener-callback work runs on a child
 * scope ([listenerJob]) so [stop] can cancel everything in one go
 * without affecting [parentScope]. The forwarders themselves spawn
 * their own per-flow coroutines on this child scope.
 */
class HostModeRunner(
    private val backendFactory: WgBridgeBackendFactory,
    private val parentScope: CoroutineScope,
    private val tcpForwarder: TcpFlowForwarder = TcpFlowForwarder(),
    private val udpForwarder: UdpFlowForwarder = UdpFlowForwarder(),
) {
    private val started = AtomicBoolean(false)
    private val stopped = AtomicBoolean(false)

    @Volatile private var endpoint: UserspaceWgEndpoint? = null
    @Volatile private var listenerJob: Job? = null
    @Volatile private var listenerScope: CoroutineScope? = null
    // per-bridge catchall forwarder lifecycle. Closed in
    // stop() *before* the endpoint so the JVM-side handlers stop
    // receiving callbacks before the gvisor netstack tears down.
    @Volatile private var tcpCatchall: AutoCloseable? = null
    @Volatile private var udpCatchall: AutoCloseable? = null
    // through-host packet forwarder (Option B). Lifecycle
    // mirrors the catchalls — closed before the endpoint.
    @Volatile private var hostForwarder: AutoCloseable? = null

    /**
     * Open the userspace WG endpoint, apply the UAPI config, and
     * start the TCP/UDP listeners.
     *
     * On any error we close the endpoint and bubble the exception
     * up; the caller should consider the runner unusable and
     * construct a fresh one if it wants to retry. Calling [start]
     * a second time is a programming error and throws
     * IllegalStateException.
     */
    @Throws(Exception::class)
    fun start(config: HostModeRunnerConfig) {
        check(started.compareAndSet(false, true)) { "runner already started" }
        val backend = backendFactory.open(
            localAddr = config.localAddr,
            mtu = config.mtu,
            listenPort = config.listenPort,
        )
        val ep = UserspaceWgEndpoint(backend)
        try {
            ep.configure(config.renderUapi())
            val job = SupervisorJob(parentScope.coroutineContext[Job])
            val scope = CoroutineScope(parentScope.coroutineContext + job)

            // **full-tunnel catchall path.** When the runner
            // is configured with handler factories, install gvisor
            // protocol-level catchalls that net every joiner-side
            // SYN / datagram and forward via OS sockets on the
            // phone's normal network. Mutually exclusive with the
            // per-port listener path below (gvisor's
            // SetTransportProtocolHandler is single-slot).
            //
            // **through-host packet forwarder.** When
            // `hostForwarderSubnet` is set we ALSO install the
            // Option B forwarder so non-local-dst traffic (1.1.1.1
            // etc.) gets re-injected as temp-local + picked up by
            // the catchalls. See `host_forwarder.go` for the
            // architecture. Installing the catchalls is a
            // prerequisite — without them the re-injected TCP/UDP
            // packets have no transport handler.
            val tcpFactory = config.tcpCatchallFactory
            val udpFactory = config.udpCatchallFactory
            if (tcpFactory != null || udpFactory != null) {
                if (tcpFactory != null) {
                    val handler = tcpFactory(scope)
                    tcpCatchall = ep.installTcpCatchall(handler, scope)
                }
                if (udpFactory != null) {
                    val handler = udpFactory(scope)
                    udpCatchall = ep.installUdpCatchall(handler, scope)
                }
                val subnet = config.hostForwarderSubnet
                if (subnet != null) {
                    hostForwarder = ep.installHostForwarder(subnet)
                }
            } else {
                // Legacy per-port-listener path. Used by tests that
                // pre-date the catchall (HostNativeListenerTest etc.)
                // and as a building block for future hostname-based
                // forwarders.
                for (port in config.tcpPorts) {
                    ep.listenTcp(
                        port = port,
                        scope = scope,
                        targetResolver = config.targetResolver,
                        onConnection = { conn -> tcpForwarder.forward(conn) },
                    )
                }
                for (port in config.udpPorts) {
                    ep.listenUdp(
                        port = port,
                        scope = scope,
                        targetResolver = config.targetResolver,
                        onFlow = { flow -> udpForwarder.forward(flow) },
                    )
                }
            }
            endpoint = ep
            listenerScope = scope
            listenerJob = job
        } catch (t: Throwable) {
            try { hostForwarder?.close() } catch (_: Exception) {}
            try { tcpCatchall?.close() } catch (_: Exception) {}
            try { udpCatchall?.close() } catch (_: Exception) {}
            hostForwarder = null
            tcpCatchall = null
            udpCatchall = null
            try { ep.close() } catch (_: Exception) {}
            started.set(false)
            throw t
        }
    }

    /** Update the VPN protector after [start]. No-op if the runner
     * has been stopped or hasn't been started yet. */
    fun setProtector(protector: WgFdProtector?) {
        endpoint?.setProtector(protector)
    }

    /**
     * Push a fresh UAPI string into the running endpoint without
     * re-opening it. uses this to apply revocations / new
     * peer enrollments in-place — wireguard-go's `IpcSet` accepts a
     * full UAPI document and applies it as a "set state" operation.
     *
     * Throws `IllegalStateException` if called before [start] or
     * after [stop] (a fresh runner must be constructed for a
     * brand-new tunnel).
     */
    @Throws(Exception::class)
    fun reconfigureUapi(uapi: String) {
        val ep = endpoint
        check(ep != null && !stopped.get()) { "runner not running" }
        ep.configure(uapi)
    }

    /** Capture wireguard-go's current state as a UAPI dump. Empty
     * string when not running — the caller treats that as "no
     * stats this tick" without distinguishing "before-start" from
     * "after-stop". */
    fun snapshotUapi(): String =
        endpoint?.snapshotUapi() ?: ""

    /**
     * Put the running bridge into a "no-peers, no-listen" idle
     * state without closing the underlying wireguard-go device.
     *
     * **Why pause instead of stop:** closing wireguard-go and
     * re-opening it in the same process triggers a fatal
     * `bulkBarrierPreWrite: unaligned arguments` Go-runtime panic
     * (observed on the user's Android phone in 's repro). Process
     * exit + restart is the only known way to fully clean up
     * wireguard-go's package-global state. Until that's fixed
     * upstream we keep the bridge alive across user-initiated
     * disconnect / reconnect cycles and use UAPI to push it
     * between "active" and "idle" states.
     *
     * The pause UAPI:
     * - `replace_peers=true` drops the entire peer table so
     * no peer can complete a handshake.
     * - `listen_port=0` lets wireguard-go bind an ephemeral
     * port — peers configured to reach the original port
     * get nothing.
     *
     * Resume by calling [reconfigureUapi] with the full
     * (private_key + listen_port + peers) payload — wireguard-go
     * accepts that as a state replacement.
     *
     * Throws `IllegalStateException` if called before [start] or
     * after [stop]. Idempotent for repeated pause()s.
     */
    @Throws(Exception::class)
    fun pause() {
        val ep = endpoint
        check(ep != null && !stopped.get()) { "runner not running" }
        ep.configure("listen_port=0\nreplace_peers=true\n")
    }

    /** Tear down listeners + endpoint. Idempotent. */
    fun stop() {
        if (!stopped.compareAndSet(false, true)) return
        // close catchalls + host forwarder BEFORE the
        // endpoint so the JVM-side handlers stop receiving callbacks
        // and the forwarder goroutine exits before gvisor goes
        // away. Avoids a window where a late dispatch hits a
        // half-closed handler.
        try { hostForwarder?.close() } catch (_: Throwable) {}
        try { tcpCatchall?.close() } catch (_: Throwable) {}
        try { udpCatchall?.close() } catch (_: Throwable) {}
        hostForwarder = null
        tcpCatchall = null
        udpCatchall = null
        listenerJob?.cancel()
        listenerScope?.cancel()
        endpoint?.close()
        listenerJob = null
        listenerScope = null
        endpoint = null
    }

    val isRunning: Boolean
        get() = started.get() && !stopped.get()
}

/**
 * Factory that opens a [WgBridgeBackend]. In production this is a
 * call to [RealWgBridgeBackend.open] — wrapped in this interface so
 * tests can inject a fake without pulling the JNI .so onto the JVM.
 */
fun interface WgBridgeBackendFactory {
    @Throws(Exception::class)
    fun open(localAddr: String, mtu: Int, listenPort: Int): WgBridgeBackend
}

/**
 * Static (per-start) configuration for a [HostModeRunner]. Contains
 * everything needed to render the UAPI string + select listen ports.
 */
data class HostModeRunnerConfig(
    val localAddr: String,
    val listenPort: Int,
    val mtu: Int = MtuMath.DEFAULT_WG_MTU,
    val privateKeyB64: String,
    val peers: List<HostModeUapi.Peer>,
    /** TCP ports to bind on the WG-side address — **legacy
     * per-port path**. Ignored when [tcpCatchallFactory] is
     * non-null (which is the production default since ). */
    val tcpPorts: List<Int> = listOf(80, 443),
    /** UDP ports to bind on the WG-side address — legacy
     * per-port path. Ignored when [udpCatchallFactory] is
     * non-null. */
    val udpPorts: List<Int> = listOf(53),
    /** Decide where each accepted connection / datagram should
     * forward. See [UserspaceWgEndpoint.listenTcp] for the
     * semantics; null = refuse. Only consulted by the legacy
     * per-port path. */
    val targetResolver: (peerAddr: String, listenAddr: String) -> InetSocketAddress?,
    /**
     * **TCP catchall handler factory.** When non-null,
     * [HostModeRunner.start] installs a gvisor protocol-level
     * catchall + skips the per-port listener loop. Receives
     * the runner's [CoroutineScope] so the handler can launch
     * long-lived coroutines bound to the bridge's lifetime.
     */
    val tcpCatchallFactory: ((kotlinx.coroutines.CoroutineScope) -> TcpForwarderHandler)? = null,
    /** **UDP catchall handler factory.** Mirror of
     * [tcpCatchallFactory]. */
    val udpCatchallFactory: ((kotlinx.coroutines.CoroutineScope) -> UdpForwarderHandler)? = null,
    /**
     * **through-host packet forwarder, peer subnet (CIDR).**
     * When non-null AND a catchall factory is also configured,
     * [HostModeRunner.start] installs the Option B host forwarder
     * (see `wgbridge_native/host_forwarder.go`). The subnet
     * should be the WG-side network (e.g. "10.99.0.0/24") so the
     * forwarder keeps host↔joiner traffic on NIC1 and only
     * intercepts traffic destined elsewhere.
     *
     * Null = no host forwarder; non-local destinations get
     * dropped at the netstack's IP layer (legacy behavior).
     * Tests that don't need through-host forwarding leave this
     * null.
     */
    val hostForwarderSubnet: String? = null,
) {
    /** Render to UAPI bytes for the wgbridge. The default emits
     * `replace_peers=true` so reconfigures after a revoke don't
     * leave the removed peer alive in wireguard-go's table. See
     * [HostModeUapi.render] for details. */
    fun renderUapi(replacePeers: Boolean = true): String =
        HostModeUapi.render(privateKeyB64, listenPort, peers, replacePeers)
}
