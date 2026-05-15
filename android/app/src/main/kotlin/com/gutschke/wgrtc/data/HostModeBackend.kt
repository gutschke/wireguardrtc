package com.gutschke.wgrtc.data

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.InetSocketAddress

/**
 * host backend: owns at most one [HostModeRunner] at a time
 * and exposes a suspend-friendly start / stop / reconfigure surface
 * for the view-model.
 *
 * Every lifecycle entry point wraps its body in
 * `withContext(Dispatchers.IO)`. The wireguard-go calls reached via
 * JNI (configure / pause / stop) block on a device-wide mutex that a
 * busy peer goroutine can hold for an unbounded time — invoking
 * them on the caller's dispatcher (typically Main) pins the UI and
 * triggers an input ANR. See
 * `feedback_jni_calls_off_main_thread.md`.
 *
 * `start` / `stop` / `reconfigure` are not mutually thread-safe; the
 * view-model serialises them through `viewModelScope.launch`.
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
    @Volatile private var runner: HostModeRunner? = null
    @Volatile private var activeId: String? = null
    /** ID of the tunnel the [runner] currently *belongs to* — even
     * when the user has tapped Disconnect (i.e. we paused). Used
     * to decide whether the next [start] can reuse the bridge or
     * must close + open a fresh one. */
    @Volatile private var ownerId: String? = null

    /** ID of the host tunnel currently up under , or null. */
    val activeTunnelId: String?
        get() = activeId

    /**
     * Bring up [tunnel] as a host. Cheapest-path first:
     * 1. **Resume:** runner already owns this tunnel — reissue the
     * UAPI to un-pause. Avoids the close+reopen crash risk.
     * 2. **Replace:** runner owns a different tunnel — close it,
     * open a fresh one.
     * 3. **Cold start:** no runner.
     */
    @Throws(Exception::class)
    suspend fun start(tunnel: Tunnel) {
        check(activeId == null) { "another tunnel is already running" }
        val cfg = tunnel.toRunnerConfig()
        withContext(Dispatchers.IO) {
            if (runner != null && ownerId == tunnel.id) {
                runner!!.reconfigureUapi(cfg.renderUapi())
                activeId = tunnel.id
                return@withContext
            }
            if (runner != null) {
                try { runner!!.stop() } catch (_: Throwable) {}
                runner = null
                ownerId = null
            }
            val r = HostModeRunner(factory, parentScope)
            r.start(cfg)
            runner = r
            ownerId = tunnel.id
            activeId = tunnel.id
        }
    }

    /**
     * Pause the active tunnel — drops peers and unbinds the listen
     * port via UAPI, but keeps the wireguard-go device alive so the
     * next [start] can reuse it. Idempotent.
     */
    suspend fun stop() {
        val r = runner ?: return
        if (activeId == null) return
        withContext(Dispatchers.IO) {
            try { r.pause() } catch (_: Throwable) {}
        }
        activeId = null
    }

    /**
     * Real shutdown for app exit / tunnel deletion. Closes the
     * wireguard-go device; the next [start] re-opens from scratch
     * (close+reopen of the same tunnel can crash — prefer [stop]).
     */
    suspend fun teardown() {
        withContext(Dispatchers.IO) {
            runner?.stop()
        }
        runner = null
        ownerId = null
        activeId = null
    }

    /**
     * Push a fresh wg-quick config without a DOWN→UP cycle. Silent
     * no-op if no tunnel is running, or if [tunnel].id doesn't match
     * the active one (handles stale ViewModel callbacks after stop).
     */
    suspend fun reconfigure(tunnel: Tunnel) {
        val r = runner ?: return
        if (tunnel.id != activeId) return
        val uapi = tunnel.toRunnerConfig().renderUapi()
        withContext(Dispatchers.IO) { r.reconfigureUapi(uapi) }
    }

    /** Forward a VpnService-backed protector into the live runner.
     * No-op if not running. Caller is responsible for re-calling
     * this after each [start] — the runner forgets the protector
     * on stop(). */
    fun setProtector(protector: WgFdProtector?) {
        runner?.setProtector(protector)
    }

    /**
     * Snapshot of wireguard-go's current state, parsed into a
     * [UapiStats] so the view-model can feed `_throughput` and
     * `_peerStats` from a uniform shape regardless of mode. Returns
     * `null` when no tunnel is running, when the snapshot fails (the
     * caller treats this as "skip this tick"), or when the UAPI
     * dump is empty.
     */
    fun snapshotStats(): UapiStats? {
        val r = runner ?: return null
        val raw = try { r.snapshotUapi() } catch (_: Throwable) { return null }
        if (raw.isEmpty()) return null
        return UapiStatsParser.parse(raw)
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
