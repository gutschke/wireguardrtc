package com.gutschke.wgrtc.data

import android.content.Context
import android.util.Log
import com.gutschke.wgrtc.signalling.EndpointCandidate
import com.gutschke.wgrtc.signalling.EndpointUpdate
import com.gutschke.wgrtc.signalling.EnrollUri
import com.gutschke.wgrtc.signalling.formatEndpoint
import com.gutschke.wgrtc.signalling.JavaIfaceAddrProvider
import com.gutschke.wgrtc.signalling.NatType
import com.gutschke.wgrtc.signalling.OfferListener
import com.gutschke.wgrtc.signalling.OfferSender
import com.gutschke.wgrtc.signalling.SignalWakeSender
import com.gutschke.wgrtc.signalling.StunClient
import com.gutschke.wgrtc.signalling.classifyNat
import com.gutschke.wgrtc.signalling.deriveSigboxKey
import com.gutschke.wgrtc.signalling.enumerateAndRank
import com.gutschke.wgrtc.signalling.parseAllowedIps
import com.gutschke.wgrtc.signalling.pubKeyFromPrivate
import com.gutschke.wgrtc.signalling.routingId
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import java.util.Base64 as JBase64

/**
 * Application-scoped owner of the long-lived `OfferListener` instances
 * (one per ENROLL-source tunnel). Lives outside the Activity and
 * ViewModel so it keeps running through configuration changes,
 * Activity destruction, and (with the help of [com.gutschke.wgrtc.OfferListenerService])
 * the application going to background.
 *
 * Public API is small on purpose:
 * - [start] / [stop] / [stopAll] manage a listener for a tunnel id.
 * - [activeCount] / [activeCountFlow] track how many are running
 * (the foreground service uses this to decide whether to post or
 * dismiss its notification).
 * - [endpointUpdates] emits (tunnelId, ip, port) whenever a
 * listener delivers a fresh OFFER and the hub has rewritten the
 * stored Endpoint = line in tunnels.json.
 *
 * The hub is the *single* writer to `tunnels.json` for endpoint
 * rewrites. ViewModel is a downstream observer. This avoids two
 * sources of truth racing on disk.
 */
class ListenerHub internal constructor(
    private val store: TunnelStore,
    private val wakeSender: SignalWakeSender,
    private val nowMs: () -> Long,
) {
    /**
     * Optional host-mode wg-go reconfigurer. When set, a
     * successful inbound ENROLL persists the new peer AND triggers
     * this callback (typically a `setState(DOWN)→setState(UP, cfg)`
     * cycle in [com.gutschke.wgrtc.WgrtcViewModel]). Null is fine
     * for client-only deployments and unit tests — the listener
     * still persists; the host's wg-go just won't accept the new
     * peer until the user manually toggles the tunnel.
     *
     * Exposed as a `var` rather than a constructor parameter so the
     * ViewModel can register itself after the application's hub
     * singleton is already constructed (cycle-of-construction).
     */
    @Volatile var hostReconfigurer: HostModeReconfigurer? = null
    constructor(context: Context) : this(
        store = TunnelStore(context),
        wakeSender = OfferSender(),
        nowMs = { System.currentTimeMillis() },
    )

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val listeners = mutableMapOf<String, OfferListener>()
    private val collectorJobs = mutableMapOf<String, Job>()
    /** Per-tunnel timestamp of the most recent [wake] dispatch. Used
     * for [WAKE_DEBOUNCE_MS] coalescing so a connect-then-foreground
     * storm doesn't fire three wakes in 200 ms. */
    private val lastWakeAtMs = mutableMapOf<String, Long>()

    /** Per-tunnel cache of the most recent candidate list received from
     * the daemon. Updated by the listener collector (Step F.3); read
     * by [latestCandidates] when `WgrtcViewModel.connect` builds a
     * [com.gutschke.wgrtc.signalling.ConnectionRunner] attempt.
     * Empty list means "no OFFER seen yet" — the runner falls back
     * to the persisted `Endpoint = ` line as a single candidate. */
    private val latestCandidatesByTunnel = mutableMapOf<String, List<EndpointUpdate>>()

    /** Per-tunnel timestamp of when [latestCandidatesByTunnel] was last
     * refreshed (epoch ms). Lets the ViewModel decide whether the
     * cached candidates are fresh enough for an immediate race or a
     * short wait-for-fresh-OFFER is warranted. */
    private val candidateTimestamps = mutableMapOf<String, Long>()

    /** Fires when the candidate cache for the named tunnel updates.
     * ViewModel.connect awaits this with a timeout right after firing
     * a wake, so the runner runs against the freshest list rather
     * than a stale one. `replay = 0` — we only care about
     * events that happen *after* connect started waiting. */
    private val _candidateRefresh = MutableSharedFlow<String>(
        replay = 0, extraBufferCapacity = 16,
        onBufferOverflow = BufferOverflow.DROP_OLDEST,
    )
    val candidateRefresh: SharedFlow<String> = _candidateRefresh.asSharedFlow()

    /** Age in ms of the cached candidate list for [tunnelId], or null
     * if no list has been cached yet. helper. */
    fun candidateAgeMs(tunnelId: String): Long? =
        candidateTimestamps[tunnelId]?.let { nowMs() - it }

    /** Single store-write mutex. Both the listener-driven endpoint
     * rewrite ([applyEndpointUpdate]) and the race-driven endpoint
     * rewrite ([rewriteEndpoint]) acquire this around their
     * load/save pair so concurrent writers don't lose updates.
     * of the candidate-negotiation v2 review. */
    private val storeMutex = Mutex()

    private val _activeCountFlow = MutableStateFlow(0)
    val activeCountFlow: StateFlow<Int> = _activeCountFlow.asStateFlow()
    val activeCount: Int get() = _activeCountFlow.value

    /** Each successful endpoint update fires here so observers (the
     * ViewModel) can refresh their UI state without re-reading the
     * whole tunnels.json. */
    private val _endpointUpdates = MutableSharedFlow<EndpointApplied>(
        replay = 0, extraBufferCapacity = 16,
        onBufferOverflow = BufferOverflow.DROP_OLDEST,
    )
    val endpointUpdates: SharedFlow<EndpointApplied> = _endpointUpdates.asSharedFlow()

    /**
     * (Re-)attach listeners for every ENROLL tunnel currently in
     * the store, and stop any that no longer match. Called both at
     * Application onCreate (to start fresh after a process restart)
     * and from [com.gutschke.wgrtc.OfferListenerService] each time
     * the service receives a new command — the service is the
     * single foreground "lifecycle anchor" so the system keeps the
     * process alive.
     */
    fun reconcileFromStore() {
        val tunnels = store.load()
        // Both ENROLL (client-mode) and HOST_MODE tunnels run a
        // long-lived broker listener — the former to receive OFFERs
        // from the daemon, the latter to receive inbound ENROLL
        // requests from new clients.
        val wantedIds = tunnels
            .filter { it.source == Tunnel.Source.ENROLL ||
                      it.source == Tunnel.Source.HOST_MODE }
            .map { it.id }.toSet()
        val stale = listeners.keys.filterNot { it in wantedIds }
        for (id in stale) stop(id)
        for (t in tunnels) {
            if (listeners.containsKey(t.id)) continue
            when (t.source) {
                Tunnel.Source.ENROLL -> start(t)
                Tunnel.Source.HOST_MODE -> startHostMode(t)
                else -> { /* skip */ }
            }
        }
    }

    /** Idempotent — a second call for the same tunnel id is a no-op. */
    fun start(tunnel: Tunnel) {
        if (listeners.containsKey(tunnel.id)) return
        val crypto = cryptoFor(tunnel) ?: return

        val listener = OfferListener()
        listeners[tunnel.id] = listener
        _activeCountFlow.value = listeners.size

        val deadlockRanges = effectiveRejectIfInside(tunnel.configText)

        scope.launch {
            listener.start(scope, crypto.brokerWss, crypto.brokerKey,
                crypto.ourPubB64, crypto.saltBytes, crypto.sigboxKey,
                rejectIfInside = deadlockRanges)
        }
        collectorJobs[tunnel.id] = scope.launch {
            listener.updates.collect { update ->
                applyEndpointUpdate(tunnel.id, update.ip, update.port)
            }
        }
        // Step F.3: cache the FULL candidate list from each OFFER so
        // a subsequent Connect can race them. Two collectors here is
        // fine — both are non-blocking tryEmit consumers.
        scope.launch {
            listener.candidateUpdates.collect { list ->
                latestCandidatesByTunnel[tunnel.id] = list
                candidateTimestamps[tunnel.id] = nowMs()
                _candidateRefresh.tryEmit(tunnel.id)
            }
        }
    }

    /**
     * Start a host-mode broker listener for [tunnel] (5). The
     * listener registers under `routing_id(host_pub, salt)` and
     * dispatches inbound `kind=enroll` envelopes through
     * [InboundEnrollHandler] → [HostModeDispatcher] → on success,
     * [applyEnrollmentToTunnel].
     *
     * No-op if [tunnel] is missing the host-mode crypto materials
     * (broker URL / key / salt). Idempotent.
     */
    fun startHostMode(tunnel: Tunnel) {
        if (listeners.containsKey(tunnel.id)) return
        val hostMode = tunnel.hostMode ?: return
        val crypto = hostCryptoFor(tunnel) ?: return

        val pendingStore = pendingTokensFor(tunnel.id)

        val handler = InboundEnrollHandler(
            tokens = pendingStore,
            nowMs = { nowMs() },
            nowSec = { nowMs() / 1000 },
        )

        val listener = OfferListener()
        listeners[tunnel.id] = listener
        _activeCountFlow.value = listeners.size

        // One-shot NAT classification per listener startup ( wiring).
        // Cached as an AtomicReference so the hostStateProvider closure
        // (which runs on every inbound ENROLL) reads the freshest known
        // value without re-classifying. Initial value `null` means
        // "classification still in progress" — we treat that as
        // "don't advertise public endpoint" (conservative). When
        // classification completes:
        //
        // - CONE_PRESERVING / CONE_REMAPPED → publicEndpointHint set
        // to "<external-ip>:<listenPort>", clients can hole-punch.
        // - SYMMETRIC / UNKNOWN → publicEndpointHint stays null;
        // clients fall back to LAN candidates only (cellular
        // hole-punch is mathematically infeasible against a
        // symmetric NAT, per CLAUDE.md / PLAN §4.6).
        val natResult = java.util.concurrent.atomic.AtomicReference<NatHint?>(null)
        scope.launch {
            try {
                val r = classifyNat(DEFAULT_STUN_SERVERS,
                    client = StunClient(timeoutMs = 2000))
                Log.i(TAG,
                    "host-mode NAT classification for ${tunnel.id}: " +
                    "type=${r.natType} ip=${r.externalIp}; ${r.note}")
                natResult.set(NatHint(r.natType, r.externalIp))
            } catch (t: Throwable) {
                Log.w(TAG,
                    "host-mode NAT classification failed for ${tunnel.id}; " +
                    "falling back to LAN-only candidates", t)
                natResult.set(NatHint(NatType.UNKNOWN, null))
            }
        }

        val dispatcher = HostModeDispatcher(
            handler = handler,
            hostStateProvider = {
                val current = store.load().firstOrNull { it.id == tunnel.id }
                    ?: error("host-mode tunnel ${tunnel.id} disappeared")
                val hm = current.hostMode
                    ?: error("host-mode field gone from tunnel ${tunnel.id}")
                val listenPort = parseListenPort(current.configText) ?: DEFAULT_HOST_PORT
                buildHostState(current, hm, crypto, listenPort, natResult.get())
            },
            applyEnrollment = { peer ->
                applyEnrollmentToTunnel(
                    store = store, tunnelId = tunnel.id, peer = peer,
                    nowMs = nowMs(), reconfigurer = hostReconfigurer,
                )
            },
            sendVia = { env -> listener.sendThrough(env) },
            scope = scope,
        )

        scope.launch {
            listener.startHostMode(
                parentScope = scope,
                brokerWss = crypto.brokerWss,
                brokerKey = crypto.brokerKey,
                hostPubBase64 = crypto.pubB64,
                saltBytes = crypto.saltBytes,
                onPayload = dispatcher::onMessage,
            )
        }
    }

    /** Cached NAT classification result for a host-mode listener. */
    private data class NatHint(
        val type: NatType,
        val externalIp: String?,
    )

    /**
     * Build a [InboundEnrollHandler.HostState] for [tunnel] using
     * fresh iface enumeration and the cached NAT classification
     *. Lifted to a method so the hostStateProvider closure
     * stays small and so this code path is reachable from tests if
     * we ever add hub-level host-mode integration tests.
     */
    private fun buildHostState(
        tunnel: Tunnel,
        hm: HostModeConfig,
        crypto: HostCrypto,
        listenPort: Int,
        natHint: NatHint?,
    ): InboundEnrollHandler.HostState {
        val ifaceCandidates = try {
            enumerateAndRank(
                provider = JavaIfaceAddrProvider(),
                // We don't reliably know which iface routes the
                // default cellular path from inside an unprivileged
                // app; mark all globally-routable IPs as
                // non-default (rank 30) rather than guessing.
                // Practically irrelevant for hosts: cellular
                // typically presents as CGNAT (rank 50, kind=lan)
                // anyway.
                defaultIface = null,
            )
        } catch (t: Throwable) {
            Log.w(TAG, "iface enumeration failed; advertising no candidates", t)
            emptyList()
        }
        // Convert each iface candidate to the wire-format
        // EndpointCandidate. Port is always the host's listen port
        // (the kernel uses the same NAT mapping for any source-port
        // from the same internal port — assuming cone NAT).
        val wireCandidates = ifaceCandidates.map { ic ->
            EndpointCandidate(ip = ic.ip, port = listenPort, kind = ic.kind)
        }.toMutableList()

        // Append the STUN-discovered public IP iff classification
        // says it's reachable (cone NAT). Symmetric / unknown →
        // omit, per PLAN §4.6.
        val publicHint: String? = when (natHint?.type) {
            NatType.CONE_PRESERVING, NatType.CONE_REMAPPED -> {
                val ip = natHint.externalIp
                if (ip != null && wireCandidates.none { it.ip == ip }) {
                    wireCandidates.add(
                        EndpointCandidate(ip = ip, port = listenPort, kind = "stun"))
                }
                natHint.externalIp?.let { formatEndpoint(it, listenPort) }
            }
            else -> null // symmetric / unknown / null (still classifying)
        }

        return InboundEnrollHandler.HostState(
            serverPrivBytes = crypto.privBytes,
            serverPubB64 = crypto.pubB64,
            listenPort = listenPort,
            hostIp = parseAddressIp(tunnel.configText) ?: hostIpFromSubnet(hm.subnet),
            subnet = hm.subnet,
            saltBytes = crypto.saltBytes,
            publicEndpointHint = publicHint,
            candidates = wireCandidates,
            allocatedIps = allocatedIps(tunnel),
        )
    }

    /** Most recent candidate list the listener observed for [tunnelId],
     * or empty list if no OFFER has arrived since the listener started.
     * [com.gutschke.wgrtc.signalling.ConnectionRunner] consumes this
     * in [com.gutschke.wgrtc.WgrtcViewModel.connect] to race
     * candidates rather than blindly using the persisted `Endpoint =`. */
    fun latestCandidates(tunnelId: String): List<EndpointUpdate> =
        latestCandidatesByTunnel[tunnelId] ?: emptyList()

    /** Pre-populate the candidate cache for [tunnelId] from a source
     * other than the OFFER stream — currently the daemon's
     * ENROLL_OK response, which carries the same ranked list so the
     * very first Connect can race LAN/STUN candidates without waiting
     * for an asynchronous OFFER cycle (which the daemon skips for
     * peers that are already UP). Idempotent: a later OFFER
     * overwrites the seed. No-op if [list] is empty. */
    fun seedCandidates(tunnelId: String, list: List<EndpointUpdate>) {
        if (list.isEmpty()) return
        latestCandidatesByTunnel[tunnelId] = list
        candidateTimestamps[tunnelId] = nowMs()
        _candidateRefresh.tryEmit(tunnelId)
    }

    /**
     * Fire a one-shot `signal_wake` to the daemon for [tunnelId].
     * Fire-and-forget: returns immediately and dispatches the WSS
     * round-trip on [scope]. Debounced to one wake per
     * [WAKE_DEBOUNCE_MS] per tunnel — duplicate calls within the
     * window are silently dropped (think: connect() + onForeground()
     * firing back-to-back).
     *
     * No-op if the tunnel doesn't exist, isn't ENROLL-sourced (no
     * broker → nothing to wake), or its config is malformed.
     */
    fun wake(tunnelId: String, force: Boolean = false) {
        val now = nowMs()
        val last = lastWakeAtMs[tunnelId] ?: 0L
        if (!force && now - last < WAKE_DEBOUNCE_MS) {
            Log.d(TAG, "wake($tunnelId): debounced (last ${now - last}ms ago)")
            return
        }
        lastWakeAtMs[tunnelId] = now

        // Dispatch to scope BEFORE the store.load — wake is called
        // from a NetworkCallback's system thread. Earlier
        // versions did the load synchronously here, blocking the
        // system thread on disk I/O. Now everything past the
        // debounce check runs on Dispatchers.IO.
        scope.launch {
            val tunnel = store.load().firstOrNull { it.id == tunnelId }
                ?: return@launch
            if (tunnel.source != Tunnel.Source.ENROLL) return@launch
            val crypto = cryptoFor(tunnel) ?: return@launch
            val dstId = routingId(crypto.serverPubB64, crypto.saltBytes)
            // The wake rides the listener's already-OPEN session so the
            // broker tags our OFFER with src=routing_id(my_pub, salt) —
            // the only id the daemon's _handle_signaling will dispatch
            // on. Listener lookup is inside the closure (rather than
            // eagerly at the top of wake()) so tests can mock the
            // SignalWakeSender without standing up a real OfferListener
            // — the FakeSender in unit tests records the call and never
            // invokes sendVia. In production, we wait up to 3 s for
            // OPEN; if the listener is mid-reconnect we fall back to
            // the daemon's periodic OFFER (~60 s cadence).
            val sendVia: suspend (String) -> Boolean = sv@{ env ->
                val listener = listeners[tunnelId]
                if (listener == null) {
                    Log.d(TAG, "wake($tunnelId): no listener registered")
                    return@sv false
                }
                if (!listener.awaitSessionOpen(3_000L)) {
                    Log.d(TAG,
                        "wake($tunnelId): listener not OPEN within 3s; skipping")
                    return@sv false
                }
                listener.sendThrough(env)
            }
            val ok = wakeSender.sendWake(
                sendVia = sendVia,
                sigboxKey = crypto.sigboxKey,
                dstRoutingId = dstId,
            )
            if (!ok) Log.d(TAG, "wake($tunnelId): sendWake reported failure")
        }
    }

    private data class TunnelCrypto(
        val brokerWss: String,
        val brokerKey: String,
        val ourPubB64: String,
        val serverPubB64: String,
        val saltBytes: ByteArray,
        val sigboxKey: ByteArray,
    )

    /** Crypto materials for a host-mode listener (no peer
     * pubkey / sigboxKey needed — the host derives a per-(client,
     * token) sigbox key on each ENROLL request inside the
     * [InboundEnrollHandler]). */
    private data class HostCrypto(
        val brokerWss: String,
        val brokerKey: String,
        val privBytes: ByteArray,
        val pubB64: String,
        val saltBytes: ByteArray,
    )

    private fun hostCryptoFor(tunnel: Tunnel): HostCrypto? {
        val brokerWss = tunnel.brokerWss ?: return null
        val brokerKey = tunnel.brokerKey ?: return null
        val saltB64 = tunnel.saltB64 ?: return null
        val priv = configValue(tunnel.configText, "PrivateKey") ?: return null
        val privBytes = try { JBase64.getDecoder().decode(priv) }
                        catch (_: Exception) { return null }
        val pubBytes = try { pubKeyFromPrivate(privBytes) }
                       catch (t: Throwable) {
                           Log.w(TAG, "pubKeyFromPrivate failed", t); return null
                       }
        val pubB64 = JBase64.getEncoder().encodeToString(pubBytes)
        val saltPadded = saltB64 + when (saltB64.length % 4) {
            2 -> "=="; 3 -> "="; else -> ""
        }
        val saltBytes = try { JBase64.getUrlDecoder().decode(saltPadded) }
                        catch (_: Exception) { return null }
        return HostCrypto(brokerWss, brokerKey, privBytes, pubB64, saltBytes)
    }

    /**
     * Mint a fresh enrollment token for the host-mode tunnel
     * [tunnelId] and return a `wgrtc-enroll://v1?...` URI the caller
     * can render as a QR (or paste into a wormhole-code flow).
     *
     * The token is added to the per-tunnel
     * [PendingTokensStore]; it's single-use and expires after [ttlMs]
     * milliseconds. [nameHint] surfaces in the host's UI as a label
     * for the resulting peer.
     *
     * Returns null when:
     * - no such tunnel exists,
     * - the tunnel isn't `Source.HOST_MODE`,
     * - the tunnel is missing broker / salt / private-key fields
     * (defensive — the host-mode setup flow always populates them).
     */
    fun mintHostEnrollToken(
        tunnelId: String, nameHint: String, ttlMs: Long,
    ): String? {
        val tunnel = store.load().firstOrNull { it.id == tunnelId } ?: return null
        if (tunnel.source != Tunnel.Source.HOST_MODE) return null
        val crypto = hostCryptoFor(tunnel) ?: return null
        // Compute the host's WG public key from the private key in the
        // [Interface] block — same value that goes on the client's
        // `[Peer] PublicKey` line. EnrollUri.build expects raw bytes.
        val pubBytes = try {
            JBase64.getDecoder().decode(crypto.pubB64)
        } catch (t: Throwable) {
            Log.w(TAG, "mintHostEnrollToken: pub b64 decode failed", t)
            return null
        }
        val tokens = pendingTokensFor(tunnelId)
        val minted = try {
            tokens.mint(nameHint, ttlMs, now = nowMs())
        } catch (t: Throwable) {
            Log.w(TAG, "mintHostEnrollToken: mint failed", t)
            return null
        }
        val uri = EnrollUri.build(
            serverPub = pubBytes,
            salt = crypto.saltBytes,
            brokerWss = crypto.brokerWss,
            brokerKey = crypto.brokerKey,
            token = minted.tokenSecret,
            // expiresAt is hint-only per EnrollUri's trust model; emit
            // it so QR scanners can show a human-readable countdown
            // without round-tripping through us. Daemon-side / host-
            // side enforcement is the authoritative check.
            expiresAt = minted.expiresAtMs / 1000,
            serverName = tunnel.name,
        )
        return uri
    }

    /** Per-host-mode-tunnel pending-tokens store path. Lives in the
     * same directory as tunnels.json so a clean uninstall removes
     * both. Token-store filenames embed the tunnel id so multiple
     * host-mode tunnels never collide. */
    private fun pendingTokensFor(tunnelId: String): PendingTokensStore {
        val parentDir = (store as? TunnelStore)
            ?.javaClass?.getDeclaredField("file")
            ?.apply { isAccessible = true }
            ?.get(store)
            ?.let { it as? java.io.File }
            ?.parentFile
            ?: java.io.File(System.getProperty("java.io.tmpdir") ?: "/tmp")
        return PendingTokensStore(java.io.File(parentDir, "host-tokens-$tunnelId.json"))
    }

    private fun parseListenPort(configText: String): Int? =
        configValue(configText, "ListenPort")?.toIntOrNull()

    private fun parseAddressIp(configText: String): String? =
        configValue(configText, "Address")?.substringBefore('/')?.trim()

    private fun hostIpFromSubnet(subnet: String): String {
        // Best-effort: assume the host claims .1 of the subnet. This
        // path runs only when the configText is malformed; the proper
        // value comes from `[Interface] Address = …`.
        val net = subnet.substringBefore('/').trim()
        val parts = net.split(".")
        if (parts.size != 4) return net
        return "${parts[0]}.${parts[1]}.${parts[2]}.1"
    }

    private fun cryptoFor(tunnel: Tunnel): TunnelCrypto? {
        val brokerWss = tunnel.brokerWss ?: return null
        val brokerKey = tunnel.brokerKey ?: return null
        val saltB64 = tunnel.saltB64 ?: return null
        val priv = configValue(tunnel.configText, "PrivateKey") ?: return null
        val serverPub = configValue(tunnel.configText, "PublicKey") ?: return null
        val privBytes = try { JBase64.getDecoder().decode(priv) }
                        catch (_: Exception) { return null }
        val pubBytes = try { JBase64.getDecoder().decode(serverPub) }
                       catch (_: Exception) { return null }
        val sigboxKey = try { deriveSigboxKey(privBytes, pubBytes) }
                        catch (t: Throwable) {
                            Log.w(TAG, "deriveSigboxKey failed for ${tunnel.id}", t)
                            return null
                        }
        val saltPadded = saltB64 + when (saltB64.length % 4) {
            2 -> "=="; 3 -> "="; else -> ""
        }
        val saltBytes = try { JBase64.getUrlDecoder().decode(saltPadded) }
                        catch (_: Exception) { return null }
        val ourPub = try {
            JBase64.getEncoder().encodeToString(pubKeyFromPrivate(privBytes))
        } catch (t: Throwable) {
            Log.w(TAG, "pubKeyFromPrivate failed", t); return null
        }
        return TunnelCrypto(brokerWss, brokerKey, ourPub, serverPub, saltBytes, sigboxKey)
    }

    fun stop(tunnelId: String) {
        val l = listeners.remove(tunnelId) ?: return
        collectorJobs.remove(tunnelId)?.cancel()
        scope.launch { l.stop() }
        _activeCountFlow.value = listeners.size
    }

    fun stopAll() {
        for (id in listeners.keys.toList()) stop(id)
    }

    /** Rewrite the `Endpoint = host:port` line in the named tunnel's
     * configText, persist, and emit on [endpointUpdates] so observers
     * can refresh. No-op if the tunnel is gone or the endpoint
     * hasn't actually changed (silences chatter when the daemon
     * re-pushes the same value).
     *
     * Holds [storeMutex] for the entire load/save window — pairs with
     * [rewriteEndpoint] (called from the race controller) so the
     * listener and the race never lose each other's writes. */
    private suspend fun applyEndpointUpdate(tunnelId: String, ip: String, port: Int) =
        storeMutex.withLock {
            val newEndpoint = formatEndpoint(ip, port)
            val tunnels = store.load()
            val current = tunnels.firstOrNull { it.id == tunnelId }
                ?: return@withLock
            val newConfig = replaceEndpointLine(current.configText, newEndpoint)
            if (newConfig == current.configText) return@withLock
            val updated = current.copy(configText = newConfig)
            val replaced = tunnels.map { if (it.id == tunnelId) updated else it }
            store.save(replaced)
            _endpointUpdates.tryEmit(EndpointApplied(tunnelId, ip, port, updated))
        }

    /** Public mutex-guarded endpoint rewriter for the race controller
     * ([WgBridgeTunnelEndpointController]). Returns the updated
     * config text after persisting; throws if the tunnel doesn't
     * exist (the race controller treats a missing tunnel as a
     * programming error since it just queried the store).
     *
     * Doesn't emit on [endpointUpdates] — that flow's contract is
     * "listener saw a new endpoint", not "the race rewrote". The
     * race's own caller knows when it switched candidates.
     *
     * of the candidate-negotiation v2 review. */
    suspend fun rewriteEndpoint(tunnelId: String, newEndpoint: String): String =
        storeMutex.withLock {
            val tunnels = store.load()
            val current = tunnels.firstOrNull { it.id == tunnelId }
                ?: error("rewriteEndpoint: no tunnel with id $tunnelId")
            val newConfig = replaceEndpointLine(current.configText, newEndpoint)
            if (newConfig == current.configText) return@withLock newConfig
            val updated = current.copy(configText = newConfig)
            val replaced = tunnels.map { if (it.id == tunnelId) updated else it }
            store.save(replaced)
            newConfig
        }

    /** Public for the ViewModel to refresh on app foregrounding —
     * the hub may have written changes while the activity was
     * away. Returns the current persisted list. */
    fun loadTunnels(): List<Tunnel> = store.load()

    /**
     * Persist the joiner produced by a wormhole-host session as a
     * new peer of [result.tunnelId]. Mirrors the enrollment-via-QR
     * flow ([applyEnrollmentToTunnel]) so the post-add reconfigure
     * (DOWN+UP cycle) runs identically.
     *
     * Suspending: TunnelStore I/O + the wg-go reconfig. Caller's
     * scope governs cancellation.
     */
    suspend fun applyWormholePeer(
        result: HostWormholeResult,
        reconfigurer: HostModeReconfigurer? = hostReconfigurer,
        nowMs: Long = nowMs(),
    ) {
        applyEnrollmentToTunnel(
            store = store,
            tunnelId = result.tunnelId,
            peer = InboundEnrollHandler.NewPeer(
                pubkeyB64 = result.joinerPubkeyB64,
                assignedIp = result.joinerIp,
                nameHint = result.joinerNameHint,
                manualInvitationText = result.manualInvitationText,
            ),
            nowMs = nowMs,
            reconfigurer = reconfigurer,
        )
    }

    /**
     * Revoke an individual enrolled peer from a host-mode tunnel.
     * Removes the peer from [HostModeConfig.enrolledPeers], persists,
     * and (if the host's wg-go is currently UP via [reconfigurer])
     * triggers a single DOWN+UP cycle so the kernel stops accepting
     * handshakes from that peer.
     *
     * The reconfigure causes a brief disconnect for *all* peers
     * (~125 ms median per `wg-tunnel JNI API surface` memory) — the
     * wg-tunnel AAR doesn't expose UAPI's per-peer remove, so a full
     * reconfigure is the only mechanism available. Transient blip
     * is the cost of revocation; not bringing the tunnel down for
     * other peers is the win over the previous "delete the whole
     * tunnel" workaround.
     */
    suspend fun revokeEnrolledPeer(
        tunnelId: String,
        pubkeyB64: String,
        reconfigurer: HostModeReconfigurer? = hostReconfigurer,
    ): Boolean = storeMutex.withLock {
        val all = store.load()
        val tunnel = all.firstOrNull { it.id == tunnelId } ?: return@withLock false
        if (tunnel.hostMode == null) return@withLock false
        val updated = tunnel.withoutEnrolledPeer(pubkeyB64)
        // No-op when the pubkey wasn't enrolled — return true so the
        // UI still feels responsive.
        if (updated === tunnel) return@withLock true
        store.save(all.map { if (it.id == tunnelId) updated else it })
        reconfigurer?.reconfigureHostTunnel(tunnelId, renderWgConfig(updated))
        true
    }

    fun saveTunnels(tunnels: List<Tunnel>) = store.save(tunnels)

    data class EndpointApplied(
        val tunnelId: String,
        val ip: String,
        val port: Int,
        val tunnel: Tunnel,
    )

    private companion object {
        const val TAG = "wgrtc-hub"
        /** Per-tunnel coalescing window for [wake]. Picked small enough
         * that a Connect-then-foreground burst fires once but a deliberate
         * retry after 5 s gets through. */
        const val WAKE_DEBOUNCE_MS = 3_000L
        /** Default UDP listen port for new host-mode tunnels. Used
         * only when the configText is malformed (missing
         * `[Interface] ListenPort`). Not load-bearing — the
         * setup UI sets the port explicitly. */
        const val DEFAULT_HOST_PORT = 51820

        /** STUN servers polled by the NAT classifier on host-
         * mode-listener startup. Three servers picked from
         * unrelated providers so a cellular carrier's transparent
         * proxying or DNS hijacking of one doesn't poison the
         * classification. Mirror of the daemon's
         * [DEFAULT_STUN_SERVERS] constant in `tests/01_stun_nat.py`. */
        val DEFAULT_STUN_SERVERS = listOf(
            "stun.l.google.com:19302",
            "stun.cloudflare.com:3478",
            "stun.nextcloud.com:3478",
        )

        fun configValue(configText: String, key: String): String? =
            configText.lineSequence()
                .firstOrNull { it.trim().startsWith(key, ignoreCase = true) &&
                               it.contains("=") }
                ?.substringAfter("=")?.trim()
    }
}

/**
 * hook for re-configuring the host's wg-go after a new peer
 * is enrolled. Production implementation (in
 * [com.gutschke.wgrtc.WgrtcViewModel]) invokes the WG-tunnel AAR's
 * `setState(DOWN)→setState(UP, newCfg)` cycle on the active host
 * tunnel. Skip-or-no-op for tunnels that aren't currently up — the
 * persisted peer entry will be picked up the next time the user
 * brings the tunnel up.
 *
 * Median cycle latency on real hardware: ~57 ms (per
 * ``) — well under the
 * WSS round-trip a client observes anyway.
 */
interface HostModeReconfigurer {
    suspend fun reconfigureHostTunnel(tunnelId: String, newConfigText: String)
}

/**
 * Persist a freshly-enrolled peer into [tunnelId]'s host-mode entry
 * in [store], then (if [reconfigurer] is non-null) hand the
 * re-rendered config to it for a wg-go DOWN+UP cycle.
 *
 * Persist-then-reconfig is the safe order: by the time the host
 * sends ENROLL_OK, the wg-go peer table already accepts the
 * client's first handshake. If the reconfig step throws, the
 * persistence stays — the operator can recover (manual toggle), and
 * the (rare) race-loss client will re-enroll.
 *
 * Hidden contract: callers must have already verified peer
 * uniqueness via [HostSubnetAllocator.nextFreeIp]; passing a
 * duplicate pubkey or IP triggers [Tunnel.withEnrolledPeer]'s guard
 * which throws [IllegalStateException].
 *
 * No-op (returns false-equivalent: silently skips) when no tunnel
 * matches [tunnelId]. Returns Unit because the caller treats any
 * exception as the failure signal — see
 * [HostModeDispatcher.applyEnrollment].
 *
 * Top-level function (not a [ListenerHub] method) so unit tests can
 * exercise the persistence + reconfig contract without instantiating
 * the full hub.
 */
suspend fun applyEnrollmentToTunnel(
    store: TunnelStore,
    tunnelId: String,
    peer: InboundEnrollHandler.NewPeer,
    nowMs: Long,
    reconfigurer: HostModeReconfigurer? = null,
) {
    val all = store.load()
    val tunnel = all.firstOrNull { it.id == tunnelId } ?: return
    val updated = tunnel.withEnrolledPeer(EnrolledPeer(
        pubkeyB64 = peer.pubkeyB64,
        assignedIp = peer.assignedIp,
        nameHint = peer.nameHint,
        enrolledAtMs = nowMs,
        manualInvitationText = peer.manualInvitationText,
    ))
    store.save(all.map { if (it.id == tunnelId) updated else it })
    reconfigurer?.reconfigureHostTunnel(tunnelId, renderWgConfig(updated))
}

/** Rewrite the `Endpoint = host:port` line in a wg-quick config block.
 * No-op if no Endpoint line. Indent (tabs vs spaces) preserved.
 * Lifted to file-level so [WgBridgeTunnelEndpointController] can
 * compute the new config text in memory before
 * [hub.rewriteEndpoint] persists it. Pure — no I/O. */
/**
 * Compute the rejectIfInside CIDR list for the OFFER decoder, given a
 * tunnel's wg-quick `[Peer] AllowedIPs`. This is the bootstrap-deadlock
 * guard (Step A): we drop candidate IPs that fall inside the tunnel's
 * own routed ranges, because using such an IP as the next Endpoint
 * would route the WG handshake back into the very tunnel that needs
 * the handshake to come up.
 *
 * Catchall ranges (`0.0.0.0/0`, `::/0`) are EXCLUDED from the filter:
 * every candidate would otherwise be rejected, leaving the listener
 * cache permanently empty for full-tunnel ENROLLs (the common case).
 * On Android, `VpnService.protect()` makes the WG handshake socket
 * bypass the tun interface, so the catchall version of the deadlock
 * can't actually happen. Narrower routes still get checked — those
 * can deadlock without policy-routing support.
 *
 * Pure function — kept top-level so unit tests can pin its behavior
 * without instantiating a [ListenerHub].
 */
internal fun effectiveRejectIfInside(configText: String): List<String> =
    parseAllowedIps(configText).filter { it != "0.0.0.0/0" && it != "::/0" }

internal fun replaceEndpointLine(configText: String, newEndpoint: String): String {
    val lines = configText.lines().toMutableList()
    var changed = false
    for (i in lines.indices) {
        val l = lines[i].trimStart()
        if (l.startsWith("Endpoint", ignoreCase = true) && l.contains("=")) {
            val indent = lines[i].substring(0, lines[i].length - l.length)
            lines[i] = "${indent}Endpoint = $newEndpoint"
            changed = true
            break
        }
    }
    return if (changed) lines.joinToString("\n") else configText
}
