package com.gutschke.wgrtc.data

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.net.InetSocketAddress
import java.util.concurrent.ConcurrentHashMap

/**
 * host backend: owns N [HostModeRunner] slots keyed by `tunnel.id`
 * and exposes a suspend-friendly start / stop / teardown /
 * reconfigure surface for the view-model. As of D4.H1 the app
 * supports running multiple host tunnels concurrently on one
 * phone — each slot is independent; the per-bridge close+reopen
 * crash risk still applies, so stop() pauses a slot rather than
 * destroying it, while teardown() commits to a real shutdown.
 *
 * Every lifecycle entry point wraps its body in
 * `withContext(Dispatchers.IO)`. The wireguard-go calls reached via
 * JNI (configure / pause / stop) block on a device-wide mutex that a
 * busy peer goroutine can hold for an unbounded time — invoking
 * them on the caller's dispatcher (typically Main) pins the UI and
 * triggers an input ANR. See
 * `feedback_jni_calls_off_main_thread.md`.
 *
 * `start` / `stop` / `reconfigure` are not mutually thread-safe per
 * slot; the view-model serialises them through
 * `viewModelScope.launch`. The slot map itself is a
 * [ConcurrentHashMap] so cross-slot operations don't trample each
 * other.
 */
class HostModeBackend(
    private val factory: WgBridgeBackendFactory,
    private val parentScope: CoroutineScope,
    private val defaultMtu: Int = MtuMath.DEFAULT_WG_MTU,
    /** Drives both the TCP forwarder's SocketFactory and the UDP
     * forwarder's egress factory. Null = OS default route. */
    private val egressSelector: EgressSelector? = null,
    /** When non-null, the UDP catchall short-circuits port-53
     * datagrams through this proxy, keeping joiner DNS on the
     * phone's resolver chain (DoH / private DNS). Null = pass
     * UDP/53 like any other UDP. */
    private val dnsProxy: DnsProxy? = null,
) {
    /**
     * One slot per tunnel id. `paused == true` means the runner is
     * still alive (the wireguard-go device is configured but bound
     * to listen_port=0 with an empty peer set) but the tunnel is
     * not counted in [activeTunnelIds]. Keeping the slot around
     * across pause/resume cycles avoids the wireguard-go
     * close+reopen panic.
     *
     * [listenPort] tracks the outer UDP bind port the slot is
     * actively listening on (or, when paused, the port it would
     * re-bind to on the next resume). D4.H4 uses it to detect
     * cross-slot port collisions before they reach wireguard-go's
     * `Bind.Open`, which would otherwise fail with an opaque
     * EADDRINUSE deep inside the JNI call.
     */
    private data class Slot(
        val runner: HostModeRunner,
        @Volatile var paused: Boolean = false,
        @Volatile var listenPort: Int = 0,
    )

    private val slots: ConcurrentHashMap<String, Slot> = ConcurrentHashMap()

    /**
     * Serialises [start] across the whole backend so two concurrent
     * cold-start calls for the same `tunnel.id` can't both win the
     * map-miss race and leak a duplicate bridge.  Class-level (not
     * per-slot) because [start] is rare and the cost of serialising
     * different-id starts is negligible compared with the JNI work
     * each one does.  The docstring still permits cross-slot
     * concurrency on stop / teardown / reconfigure — they don't take
     * this lock.
     */
    private val startMutex = Mutex()

    private val _activeTunnelIds = MutableStateFlow<Set<String>>(emptySet())
    /** Set of tunnel ids whose slot is currently UP (not paused).
     * Re-emits after every start / stop / teardown / teardownAll
     * transition. */
    val activeTunnelIds: StateFlow<Set<String>> = _activeTunnelIds.asStateFlow()

    /** Recompute [_activeTunnelIds] from the current slot map. Safe
     * to call from any thread because both ConcurrentHashMap and
     * MutableStateFlow are thread-safe. */
    private fun refreshActiveIds() {
        _activeTunnelIds.value = slots.entries
            .asSequence()
            .filter { !it.value.paused }
            .map { it.key }
            .toSet()
    }

    /**
     * Bring [tunnel] up as a host. Cheapest-path first:
     * 1. **Resume / reconfigure:** slot for this id exists (paused
     *    or not) — reissue UAPI to un-pause or refresh peers.
     *    Avoids the close+reopen crash risk.
     * 2. **Cold start:** no slot for this id — open a fresh bridge.
     *
     * Allowed when other tunnels are running; different ids never
     * share a slot, so no replace path is needed.
     */
    @Throws(Exception::class)
    suspend fun start(tunnel: Tunnel) {
        val cfg = tunnel.toRunnerConfig()
        startMutex.withLock {
            // D4.H4 — refuse to bring a slot up on a listen port that
            // another live slot is already using.  Paused slots are
            // bound to listen_port=0 so they don't collide today; when
            // the user resumes them, the same check fires again on
            // that start() and surfaces the conflict before wireguard-go
            // returns EADDRINUSE through the JNI boundary.
            val collision = slots.entries.firstOrNull { (id, slot) ->
                id != tunnel.id && !slot.paused && slot.listenPort == cfg.listenPort
            }
            if (collision != null) {
                throw PortCollisionException(
                    newTunnelId = tunnel.id,
                    existingTunnelId = collision.key,
                    port = cfg.listenPort,
                )
            }
            withContext(Dispatchers.IO) {
                val existing = slots[tunnel.id]
                if (existing != null) {
                    existing.runner.reconfigureUapi(cfg.renderUapi())
                    existing.paused = false
                    // The user may have edited ListenPort between
                    // pause and resume; keep the slot's record in
                    // sync so future collision checks reflect the
                    // live port.
                    existing.listenPort = cfg.listenPort
                    refreshActiveIds()
                    return@withContext
                }
                val r = HostModeRunner(factory, parentScope)
                try {
                    r.start(cfg)
                } catch (t: Throwable) {
                    // The runner's own start() unwinds the bridge on
                    // failure, so we just drop the reference here.
                    throw t
                }
                slots[tunnel.id] = Slot(
                    runner = r,
                    paused = false,
                    listenPort = cfg.listenPort,
                )
                refreshActiveIds()
            }
        }
    }

    /**
     * Pause the slot for [tunnelId] — drops peers and unbinds the
     * listen port via UAPI, but keeps the wireguard-go device alive
     * so the next [start] can reuse it. Idempotent; no-op when the
     * slot doesn't exist or is already paused.
     */
    suspend fun stop(tunnelId: String) {
        val slot = slots[tunnelId] ?: return
        if (slot.paused) return
        withContext(Dispatchers.IO) {
            try { slot.runner.pause() } catch (_: Throwable) {}
        }
        slot.paused = true
        refreshActiveIds()
    }

    /**
     * Real shutdown for app exit / tunnel deletion. Closes the
     * wireguard-go device and removes the slot; the next [start]
     * re-opens from scratch (close+reopen of the same tunnel can
     * crash — prefer [stop] for user-initiated disconnects).
     */
    suspend fun teardown(tunnelId: String) {
        val slot = slots.remove(tunnelId) ?: return
        withContext(Dispatchers.IO) {
            try { slot.runner.stop() } catch (_: Throwable) {}
        }
        refreshActiveIds()
    }

    /**
     * Real shutdown of every slot. Used on app exit / activity
     * finishing where the whole process is going away. Iterates
     * slots sequentially via [teardown] — a slow JNI close on one
     * slot blocks the rest of the sweep. Acceptable on app exit
     * (the process is leaving anyway) but not for hot-path shutdown.
     * D4.H3: revisit if any caller needs parallel teardown — wrap
     * the loop body in `parentScope.async { teardown(id) }` and
     * `awaitAll()`.
     */
    suspend fun teardownAll() {
        val ids = slots.keys.toList()
        for (id in ids) {
            teardown(id)
        }
    }

    /**
     * Push a fresh wg-quick config without a DOWN→UP cycle. Silent
     * no-op if no slot for [tunnel].id exists (e.g. ListenerHub
     * callbacks for a tunnel the user just tore down).
     */
    suspend fun reconfigure(tunnel: Tunnel) {
        val slot = slots[tunnel.id] ?: return
        val uapi = tunnel.toRunnerConfig().renderUapi()
        withContext(Dispatchers.IO) { slot.runner.reconfigureUapi(uapi) }
    }

    /** Forward a VpnService-backed protector into every live slot's
     * runner. No-op when no slot exists. Caller is responsible for
     * re-calling this after each [start] — the runner forgets the
     * protector on stop(). */
    fun setProtector(protector: WgFdProtector?) {
        for (slot in slots.values) {
            slot.runner.setProtector(protector)
        }
    }

    /**
     * Snapshot of wireguard-go's current state for [tunnelId],
     * parsed into a [UapiStats] so the view-model can feed
     * `_throughput` and `_peerStats` from a uniform shape regardless
     * of mode. Returns `null` when no slot exists, when the snapshot
     * fails (the caller treats this as "skip this tick"), or when
     * the UAPI dump is empty.
     */
    fun snapshotStats(tunnelId: String): UapiStats? {
        val slot = slots[tunnelId] ?: return null
        val raw = try { slot.runner.snapshotUapi() } catch (_: Throwable) { return null }
        if (raw.isEmpty()) return null
        return UapiStatsParser.parse(raw)
    }

    /**
     * Per-slot snapshot for every running tunnel, keyed by tunnel
     * id. Skips slots that fail to dump or return an empty UAPI
     * blob. Convenience for batch UI refreshes that need all
     * counters in one tick.
     */
    fun snapshotAllStats(): Map<String, UapiStats> {
        val out = mutableMapOf<String, UapiStats>()
        for ((id, _) in slots) {
            snapshotStats(id)?.let { out[id] = it }
        }
        return out
    }

    /** Convert a [Tunnel] to a [HostModeRunnerConfig]. Pulled out so
     * the view-model and tests share one canonical mapping. */
    private fun Tunnel.toRunnerConfig(): HostModeRunnerConfig {
        val hm = hostMode ?: error("tunnel ${this.id} is not a host-mode tunnel")
        val privKey = parseInterfaceField(configText, "PrivateKey")
            ?: error("[Interface] PrivateKey missing")
        val addr = parseInterfaceField(configText, "Address")
            ?: error("[Interface] Address missing")
        val listenPort = parseInterfaceField(configText, "ListenPort")
            ?.toIntOrNull()
            ?: error("[Interface] ListenPort missing or not an integer")
        val mtu = parseInterfaceField(configText, "MTU")?.toIntOrNull() ?: defaultMtu
        // V6.H1 — pass every bare address from the [Interface]
        // Address line(s) to wgbridgeNew, comma-joined.  The Go
        // side splits + parses + passes the slice through to
        // netstack.CreateNetTUN (already dual-stack-capable).
        // Falls back to the legacy single-address path if the
        // helper found nothing (defensive — `addr` already passed
        // the not-null check above, so this is unreachable).
        val parsedAddrs = parseInterfaceAddresses(configText)
        val localAddr = if (parsedAddrs.isNotEmpty()) {
            parsedAddrs.joinToString(",")
        } else {
            addr.substringBefore('/').trim()
        }
        val peers = hm.enrolledPeers.map { ep ->
            HostModeUapi.Peer(
                publicKeyB64 = ep.pubkeyB64,
                allowedIp = "${ep.assignedIp}/32",
                // V6.3 — emit a /128 v6 allowed_ip when the peer
                // has one.  Null on legacy v4-only peers.
                allowedIpV6 = ep.assignedIpV6?.let { "$it/128" },
            )
        }
        val sf = egressSelector?.socketFactory()
            ?: javax.net.SocketFactory.getDefault()
        val uef = egressSelector?.udpEgressFactory()
            ?: DatagramSocketUdpEgressFactory()
        val dnsProxyRef = dnsProxy
        val tcpFactory: (CoroutineScope) -> TcpForwarderHandler = { _ ->
            TcpForwarderHandler(
                socketFactory = sf,
                targetResolver = ::identityTargetResolver,
            )
        }
        val udpFactory: (CoroutineScope) -> UdpForwarderHandler = { _ ->
            UdpForwarderHandler(
                egressFactory = uef,
                targetResolver = ::identityTargetResolver,
                dnsProxy = dnsProxyRef,
            )
        }
        // Subnet derived from [Interface] Address (e.g. "10.99.0.1/24"
        // → "10.99.0.0/24") drives the host forwarder's NIC2 default
        // route — see host_forwarder.go. Null disables through-host
        // forwarding without breaking the local-dst path.
        //
        // V6.H2b — when the tunnel has a v6 ULA, append it
        // (comma-separated, canonical no-whitespace form per
        // WgAllowedIps).  The Go side's wgbridgeInstallHostForwarder
        // splits the comma form and installs dual-stack routes +
        // ICMPv6 transport handler accordingly.
        val v4Subnet = canonicalSubnetForAddress(addr)
        val hostForwarderSubnet = when {
            v4Subnet != null && hm.subnetV6 != null -> "$v4Subnet,${hm.subnetV6}"
            v4Subnet != null -> v4Subnet
            hm.subnetV6 != null -> hm.subnetV6
            else -> null
        }
        return HostModeRunnerConfig(
            localAddr = localAddr,
            listenPort = listenPort,
            mtu = mtu,
            privateKeyB64 = privKey,
            peers = peers,
            // Per-port path is dormant whenever the catchall is
            // installed; keep the fields populated with safe
            // defaults so the legacy path still works if anything
            // null-checks these.
            tcpPorts = emptyList(),
            udpPorts = emptyList(),
            targetResolver = REFUSE_ALL,
            tcpCatchallFactory = tcpFactory,
            udpCatchallFactory = udpFactory,
            hostForwarderSubnet = hostForwarderSubnet,
        )
    }

    private companion object {
        /** Default refuse-all resolver — only consulted by the
         * legacy per-port-listener path, which the catchall
         * factories replace under production wiring. */
        val REFUSE_ALL: (String, String) -> InetSocketAddress? = { _, _ -> null }

        /** Canonicalise the v4 subnet for the host forwarder:
         * `"10.99.0.1/24"` → `"10.99.0.0/24"`.  Null on parse
         * failure or v6 input — v6 is appended separately by the
         * caller via the comma-form (`subnetV6` is already in
         * network form, no canonicalisation needed). */
        fun canonicalSubnetForAddress(addr: String): String? {
            val slash = addr.indexOf('/')
            if (slash <= 0) return null
            val ipStr = addr.substring(0, slash).trim()
            val prefix = addr.substring(slash + 1).trim().toIntOrNull()
                ?: return null
            if (prefix !in 0..32) return null
            val ip = try {
                java.net.InetAddress.getByName(ipStr)
            } catch (_: Throwable) { return null }
            if (ip !is java.net.Inet4Address) return null
            val bytes = ip.address
            // Mask host bits to zero.
            val keep = prefix
            for (i in 0 until 4) {
                val bitsInByte = (keep - i * 8).coerceIn(0, 8)
                val mask = if (bitsInByte == 0) 0 else (0xff shl (8 - bitsInByte)) and 0xff
                bytes[i] = (bytes[i].toInt() and mask).toByte()
            }
            return "${bytes[0].toInt() and 0xff}.${bytes[1].toInt() and 0xff}." +
                "${bytes[2].toInt() and 0xff}.${bytes[3].toInt() and 0xff}/$prefix"
        }

        /** Catchall target resolver: forward to exactly the address
         * the joiner targeted. Validates `origDest` defensively
         * since gvisor's String() format is the only contract. */
        fun identityTargetResolver(
            @Suppress("UNUSED_PARAMETER") peer: String, origDest: String,
        ): InetSocketAddress? {
            val colon = origDest.lastIndexOf(':')
            if (colon <= 0 || colon == origDest.length - 1) return null
            val host = origDest.substring(0, colon)
                .trim().trim('[', ']')
            val port = origDest.substring(colon + 1).trim().toIntOrNull()
                ?: return null
            if (port !in 1..65535) return null
            return try { InetSocketAddress(host, port) }
            catch (_: Throwable) { null }
        }
    }
}

/**
 * Thrown by [HostModeBackend.start] when the requested tunnel's
 * `ListenPort` is already bound by another active host tunnel in the
 * same process.  wireguard-go's UDP bind would otherwise fail deep
 * inside the JNI call with an opaque EADDRINUSE; the typed exception
 * lets the view-model surface a user-actionable message ("pause the
 * other tunnel or pick a different port").
 *
 * Paused slots are bound to listen_port=0 and don't conflict at the
 * kernel level; the same check fires again when the user resumes
 * them, so this exception captures both cold-start and resume races.
 */
class PortCollisionException(
    val newTunnelId: String,
    val existingTunnelId: String,
    val port: Int,
) : IllegalStateException(
    "Host tunnel '$newTunnelId' cannot bind UDP port $port — tunnel " +
        "'$existingTunnelId' is already using it. Pause that tunnel or " +
        "choose a different ListenPort.",
)
