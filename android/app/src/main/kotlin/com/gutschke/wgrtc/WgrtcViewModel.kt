package com.gutschke.wgrtc

import android.app.Application
import android.util.Log
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.gutschke.wgrtc.data.ActiveTunnelTracker
import com.gutschke.wgrtc.data.HostModeFactory
import com.gutschke.wgrtc.data.HostModeReconfigurer
import com.gutschke.wgrtc.data.JoinerNController
import com.gutschke.wgrtc.data.JoinerNEndpointReconfigurer
import com.gutschke.wgrtc.data.JoinerNVpnBinding
import com.gutschke.wgrtc.data.JoinerVpnBinding
import com.gutschke.wgrtc.data.JoinerVpnConfig
import com.gutschke.wgrtc.data.bindJoinerNVpnService
import com.gutschke.wgrtc.data.ThroughputStats
import com.gutschke.wgrtc.data.WgBridgeTunnelEndpointController
import com.gutschke.wgrtc.data.bindJoinerVpnService
import com.gutschke.wgrtc.data.Tunnel
import com.gutschke.wgrtc.data.TunnelStore
import com.gutschke.wgrtc.data.WgAllowedIps
import com.gutschke.wgrtc.data.kernelConfigStream
import com.gutschke.wgrtc.data.renderEnrollConfig
import com.gutschke.wgrtc.data.NetworkChangeMonitor
import com.gutschke.wgrtc.data.WgQuickUapi
import com.gutschke.wgrtc.signalling.ConnectAttemptResult
import com.gutschke.wgrtc.signalling.ConnectionRunner
import com.gutschke.wgrtc.signalling.EndpointUpdate
import com.gutschke.wgrtc.signalling.EnrollClient
import com.gutschke.wgrtc.signalling.EnrollResult
import com.gutschke.wgrtc.signalling.EnrollUri
import com.gutschke.wgrtc.signalling.OfferListener
import com.gutschke.wgrtc.signalling.deriveSigboxKey
import com.gutschke.wgrtc.signalling.enumerateLocalInterfaces
import com.gutschke.wgrtc.signalling.pubKeyFromPrivate
import java.util.Base64 as JBase64
import com.gutschke.wgrtc.data.UapiStats
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.filter
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Single source of truth for tunnel data + connection state.
 *
 * Holds:
 * * the persisted list of tunnels (read on init from [TunnelStore]),
 * * which tunnel is currently UP (only one at a time — Android
 * permits a single concurrent VpnService),
 * * any transient error from the last enrollment / connect attempt.
 *
 * Does NOT own VPN consent — that requires an Activity, so the screens
 * fire `VpnService.prepare(...)` themselves and call back into the
 * ViewModel once consent is granted.
 */
class WgrtcViewModel(app: Application) : AndroidViewModel(app), HostModeReconfigurer {

 // Tunnel persistence is now owned by [ListenerHub] (which has
 // to write to disk from its application-scoped coroutine when
 // an OFFER lands). Routing all writes through the hub keeps a
 // single canonical writer; the ViewModel just reads via the
 // hub's `loadTunnels` / `saveTunnels` accessors.

 private val _tunnels = MutableStateFlow<List<Tunnel>>(emptyList())
 val tunnels: StateFlow<List<Tunnel>> = _tunnels.asStateFlow()

 /** The id of the joiner-side tunnel currently UP, or null.
 *
 * Joiner tunnels are subject to Android's per-process VpnService
 * singleton — at most one can be active at a time.  Host tunnels
 * use a separate slot group ([HostModeBackend.activeTunnelIds])
 * that allows N concurrent entries.
 *
 * UI should not read this directly — use [activeTunnelIds] for
 * the unified view, or [isActive] for a per-tunnel boolean. */
 private val _activeJoinerTunnelId = MutableStateFlow<String?>(null)
 val activeJoinerTunnelId: StateFlow<String?> = _activeJoinerTunnelId.asStateFlow()

 /** Set by paths that intentionally drive an in-place reconfigure
 * on a tunnel that is already UP, so a transient DOWN→UP cycle
 * in the underlying runner doesn't briefly null
 * [_activeJoinerTunnelId] and leave the UI flickering "Idle". */
 @Volatile
 private var reconfiguringTunnelId: String? = null

 /**
 * When the joiner-mode tunnel runs through wgbridge
 * (settings.joinerBackend == WGBRIDGE), [connect] binds the
 * [JoinerVpnService] and stashes the binding here so
 * [disconnect] can stop the service + unbind symmetrically.
 * Null whenever a legacy GoBackend joiner OR a host-mode
 * tunnel is the active path.
 */
 @Volatile
 private var activeJoinerBinding: JoinerVpnBinding? = null

 /**
  * Joiner-N shared VpnService binding. Held across multiple
  * joiner add/remove cycles — the kernel TUN survives those
  * swaps. Null whenever the joiner-N set is empty.
  * Gated by [SettingsStore.joinerNEnabled]; the legacy
  * single-joiner path uses [activeJoinerBinding] above.
  */
 @Volatile
 private var activeJoinerNBinding: JoinerNVpnBinding? = null

 /** Tunnel ids currently routed through the joiner-N shared
  * stack. Independent of [_activeJoinerTunnelId] — the two
  * are mutually exclusive in practice (the user toggles a
  * single flag) but the union ([activeTunnelIds]) is what
  * the UI reads. */
 private val _activeJoinerNTunnelIds = MutableStateFlow<Set<String>>(emptySet())
 val activeJoinerNTunnelIds: StateFlow<Set<String>> =
  _activeJoinerNTunnelIds.asStateFlow()

 /** State string ("DOWN", "UP", "TOGGLE", "FAILED", …) for the live tunnel. */
 private val _liveState = MutableStateFlow("DOWN")
 val liveState: StateFlow<String> = _liveState.asStateFlow()

 /**
 * Unified "what tunnels are currently up" — the union of the
 * joiner slot (at most one id) and the host slot map (N ids
 * since D4.H1).  Single source of truth for UI status badges:
 * `activeTunnelIds.value.contains(tunnel.id)`.
 *
 * Built lazily so the test seam can construct a [WgrtcViewModel]
 * subclass without a live [WgrtcApp.instance.hostModeBackend] —
 * the lazy thunk runs on first collection, by which point real
 * code has gone through `WgrtcApp.onCreate`.
 *
 * Sharing strategy: [SharingStarted.Eagerly].  Unlike the
 * per-tunnel caches below, this flow is read via `.value` by
 * non-UI paths even when the UI isn't subscribed:
 * [activeTunnelsForOverlapGate] gates `connect`, [disconnect] /
 * [disconnectAll] decide what to tear down, and the `init` block
 * reconciles after Activity recreate.  `WhileSubscribed(...)`
 * would let those `.value` reads return a stale snapshot whenever
 * no Compose collector was attached, mis-routing the disconnect
 * path.  This is the one combined flow that pays for an idle
 * collector; the per-tunnel slices below switch to
 * `WhileSubscribed` because they're leaf flows used only by the
 * UI.
 */
 val activeTunnelIds: StateFlow<Set<String>> by lazy {
 ActiveTunnelTracker.combinedFlow(
 joiner = _activeJoinerTunnelId,
 host = WgrtcApp.instance.hostModeBackend.activeTunnelIds,
 joinerN = _activeJoinerNTunnelIds,
 ).stateIn(
 viewModelScope,
 SharingStarted.Eagerly,
 ActiveTunnelTracker.union(
 _activeJoinerTunnelId.value,
 WgrtcApp.instance.hostModeBackend.activeTunnelIds.value,
 _activeJoinerNTunnelIds.value,
 ),
 )
 }

 /**
 * Per-tunnel membership flow.  Cached so two screens watching the
 * same id share a single underlying combine() pipeline — Compose
 * recomposes will re-acquire the same StateFlow on every render
 * and shouldn't churn the upstream.
 *
 * D4.H2 leak fix: sharing strategy is
 * [SharingStarted.WhileSubscribed] with a 5 s grace window so a
 * Compose screen-swap doesn't tear down the upstream collector,
 * but an unsubscribed tunnel (the user navigated away) no longer
 * keeps a permanent collector rooted in [viewModelScope].
 * [deleteTunnel] additionally evicts the cache entry so a
 * rename/delete cycle in a long-lived process can't grow the
 * cache unboundedly.  Compose-only flow — there is no non-UI
 * caller that reads `.value` for these.
 */
 private val isActiveCache = java.util.concurrent.ConcurrentHashMap<String, StateFlow<Boolean>>()
 fun isActive(tunnelId: String): StateFlow<Boolean> =
 isActiveCache.getOrPut(tunnelId) {
 activeTunnelIds
 .map { it.contains(tunnelId) }
 .distinctUntilChanged()
 .stateIn(
 viewModelScope,
 SharingStarted.WhileSubscribed(5_000),
 activeTunnelIds.value.contains(tunnelId),
 )
 }

 /** Per-tunnel live race-winner endpoint, separate from the
 * persisted Endpoint=… line in the wg-quick config. The UI
 * shows this when it differs from the persisted value, so a
 * user on the home LAN sees "Active: 198.51.100.103:22111 (LAN)"
 * while the persisted public IP stays available as a fallback
 * for cross-network reconnects.
 *
 * Lifecycle: set on race success, cleared on disconnect or DOWN.
 * Map keyed by tunnelId. */
 private val _liveEndpoints = MutableStateFlow<Map<String, EndpointUpdate>>(emptyMap())
 val liveEndpoints: StateFlow<Map<String, EndpointUpdate>> =
 _liveEndpoints.asStateFlow()

 /** Tunnel id currently in the "connecting" phase (between user's
 * Connect tap and the race's Success/Failed result), or null
 * when no connect is in flight. Drives the UI's per-row
 * progress indicator: without this, the user taps Connect and
 * sees no visual change for several seconds while the wake +
 * probe + race run, making it look as if the click didn't
 * register. */
 private val _connectingTunnelId = MutableStateFlow<String?>(null)
 val connectingTunnelId: StateFlow<String?> = _connectingTunnelId.asStateFlow()

 private val _lastError = MutableStateFlow<String?>(null)
 val lastError: StateFlow<String?> = _lastError.asStateFlow()

 /** Prominent security alert shown after a TOKEN_USED rejection.
 * for the rationale: a stolen QR can race a
 * legitimate user, but the loser receives an authenticated
 * TOKEN_USED so the failure shouldn't be a generic "server
 * rejected" red-text — it should call out what happened.
 * Cleared by [dismissTokenUsedAlert] once the user
 * acknowledges. */
 private val _tokenUsedAlert = MutableStateFlow<TokenUsedAlert?>(null)
 val tokenUsedAlert: StateFlow<TokenUsedAlert?> = _tokenUsedAlert.asStateFlow()

 fun dismissTokenUsedAlert() { _tokenUsedAlert.value = null }

 /** A snapshot of the rejected enrollment for the prominent banner.
 * [serverNote] is the daemon-supplied note (often the human-
 * readable reason ENROLL_ERR carried). */
 data class TokenUsedAlert(val serverNote: String?)

 /**
 * Sampled RX/TX counters + per-second rate keyed by tunnel id.
 * One entry per currently-active tunnel (joiner or any of the
 * N host slots).  Empty when nothing is up.  Per-tunnel readers
 * use [throughputFor] which derives a tunnel-scoped flow.
 */
 private val _throughput = MutableStateFlow<Map<String, ThroughputStats>>(emptyMap())
 val throughput: StateFlow<Map<String, ThroughputStats>> = _throughput.asStateFlow()
 private var throughputJob: Job? = null

 /** Derived per-tunnel throughput stream.  Cached so repeat
 * subscriptions for the same id share an upstream collector.
 * Sharing: [SharingStarted.WhileSubscribed] — see [isActive] for
 * the same leak-avoidance rationale.  The throughput sampler
 * still writes into [_throughput] every tick regardless of
 * subscribers; this flow is just the per-id projection that
 * Compose pulls. */
 private val throughputCache =
 java.util.concurrent.ConcurrentHashMap<String, StateFlow<ThroughputStats?>>()
 fun throughputFor(tunnelId: String): StateFlow<ThroughputStats?> =
 throughputCache.getOrPut(tunnelId) {
 _throughput
 .map { it[tunnelId] }
 .distinctUntilChanged()
 .stateIn(
 viewModelScope,
 SharingStarted.WhileSubscribed(5_000),
 _throughput.value[tunnelId],
 )
 }

 /**
 * Per-peer slice of every active tunnel's stats, outer-keyed by
 * tunnel id, inner-keyed by the peer's base64 pubkey (matches
 * [EnrolledPeer.pubkeyB64]).  Refreshed at the same ~1 Hz cadence
 * as [throughput].  Empty inner map for tunnels that haven't
 * produced peer counters yet.
 */
 private val _peerStats = MutableStateFlow<
 Map<String, Map<String, com.gutschke.wgrtc.data.PeerStats>>
 >(emptyMap())
 val peerStats: StateFlow<Map<String, Map<String, com.gutschke.wgrtc.data.PeerStats>>> =
 _peerStats.asStateFlow()

 /** Per-tunnel peer-stats stream — what the host-mode peer list
 * subscribes to via the detail screen's tunnel.id.
 * Sharing: [SharingStarted.WhileSubscribed] — see [isActive] for
 * the same leak-avoidance rationale. */
 private val peerStatsCache = java.util.concurrent.ConcurrentHashMap<
 String, StateFlow<Map<String, com.gutschke.wgrtc.data.PeerStats>>
 >()
 fun peerStatsFor(tunnelId: String): StateFlow<Map<String, com.gutschke.wgrtc.data.PeerStats>> =
 peerStatsCache.getOrPut(tunnelId) {
 _peerStats
 .map { it[tunnelId].orEmpty() }
 .distinctUntilChanged()
 .stateIn(
 viewModelScope,
 SharingStarted.WhileSubscribed(5_000),
 _peerStats.value[tunnelId].orEmpty(),
 )
 }

 /** One-shot text inbox for the Paste screen — populated by Scan/external
 * intent prefill, consumed by [PasteTunnelScreen] on its next compose. */
 private val _pendingPasteText = MutableStateFlow("")
 val pendingPasteText: StateFlow<String> = _pendingPasteText.asStateFlow()
 fun setPendingPaste(text: String) { _pendingPasteText.value = text }
 fun consumePendingPaste(): String {
 val v = _pendingPasteText.value
 _pendingPasteText.value = ""
 return v
 }

 /** Per-tunnel in-flight connect coroutines. Disconnect of
  * tunnel X cancels `connectJobs[X]` so the race teardown is
  * the last backend mutation, not racing the next setEndpoint
  * /setState(UP) of an unfinished candidate sweep.
  *
  * Keyed by tunnel id because joiner-N (and the host slot
  * group) allows multiple concurrent connects. The legacy
  * single-joiner path used a scalar field; carrying that into
  * joiner-N would let a disconnect on one tunnel cancel the
  * unrelated connect coroutine of another, silently failing
  * the second one — the J7b code-review caught this. */
 private val connectJobs = java.util.concurrent.ConcurrentHashMap<String, Job>()

 /** Joiner-N connects in flight, used by [maybeUnbindJoinerN]
  * to keep the shared service binding alive across a connect
  * that hasn't yet reached its success/failure branch. Without
  * this, an early-failing first connect could unbind the
  * service while a second concurrent connect is still inside
  * `addJoiner`, dropping the underlying LocalBinder out from
  * under wireguard-go. */
 private val joinerNConnectsInFlight = java.util.concurrent.atomic.AtomicInteger(0)

 /** roam handler. Constructed in the joiner-mode connect
 * success path; stopped on disconnect. Listens (via
 * [networkChangeMonitor]) for Android network changes and
 * drives an in-place re-race through the *existing*
 * TunnelEndpointController whenever the live handshake goes
 * stale. No JoinerVpnService rebind — just `setEndpoint` calls
 * into the running wireguard-go via UAPI. */
 @Volatile private var activeRoamController:
 com.gutschke.wgrtc.signalling.RoamController? = null

 /** Per-tunnel roam controllers for the joiner-N path. Keyed by
  * tunnel id because joiner-N permits N active joiners and each
  * needs its own roam state. The legacy single-joiner path keeps
  * the [activeRoamController] singleton above — the two coexist
  * because joiner-N tunnels never share a controller with the
  * single-joiner slot (the active sets are mutually exclusive
  * by design). */
 private val activeJoinerNRoamControllers =
  java.util.concurrent.ConcurrentHashMap<
   String, com.gutschke.wgrtc.signalling.RoamController>()

 /** Step G: network-change monitor active only while a tunnel is
 * UP. Fires a force-wake at the daemon when the routing topology
 * shifts (Wi-Fi joined/lost, hotspot toggled, etc.) so a fresh
 * OFFER lands before WG's next handshake retry. */
 private val networkChangeMonitor by lazy {
 NetworkChangeMonitor(getApplication()) {
 // ONLY fire force-wake when the tunnel is fully UP.
 //
 // The cancel-and-restart pattern (G-cancel) was tried and
 // produced a self-cancellation loop: registerNetworkCallback
 // synchronously fires onAvailable for every existing
 // network at registration time. If the monitor started
 // at connect entry, those initial callbacks would cancel
 // the connect that JUST started, restart it, fire more
 // callbacks, and so on. The wireguard-go kernel module
 // got hammered through repeated setState(UP)/setState(DOWN)
 // cycles — empirically observed in production: server saw
 // the tunnel succeed but app showed cancellation, then
 // phone rebooted (likely WG kernel module crash).
 //
 // Mid-race network-change handling is rare in practice
 // (user has to physically change networks during the 5 s
 // race). When it does happen, the listener's
 // endpointUpdates collector above will re-setState with
 // the listener's rewritten config once the daemon's
 // responsive OFFER arrives. Acceptable trade-off.
 // network-change wakes target the joiner tunnel — the joiner
 // is the side whose endpoint can roam (host tunnels are
 // entered, not joined).  Host tunnels don't need a wake on
 // network change; the daemon-side equivalent is the listener
 // path.
 val singleJoinerId = _activeJoinerTunnelId.value
 val joinerNIds = _activeJoinerNTunnelIds.value
 if (singleJoinerId == null && joinerNIds.isEmpty()) {
 return@NetworkChangeMonitor
 }
 singleJoinerId?.let {
 Log.i("wgrtc-vm", "network change → force-wake tunnel $it")
 hub.wake(it, force = true)
 }
 joinerNIds.forEach {
 Log.i("wgrtc-vm",
 "network change → force-wake joiner-N tunnel $it")
 hub.wake(it, force = true)
 }
 // Notify roam handlers so they can re-race candidates
 // if the network change made the current live endpoint
 // unreachable.  Legacy single-joiner uses a scalar
 // controller; joiner-N keys controllers by tunnel id so
 // each active joiner re-races independently against its
 // own candidate list.
 activeRoamController?.onNetworkChanged()
 for (rc in activeJoinerNRoamControllers.values) {
 rc.onNetworkChanged()
 }
 }
 }

 // (legacy GoBackend tunnel-state listener removed in the
 // wgbridge_native path manages its lifecycle through
 // activeJoinerBinding + hostModeBackend.activeTunnelIds.)

 /** Application-scoped owner of the OFFER listeners. Created
 * in [WgrtcApp.onCreate] before any ViewModel exists, so the
 * listeners survive activity destruction. */
 private val hub = WgrtcApp.instance.listenerHub

 init {
 // hook: register as the host-mode wg-go reconfigurer
 // so a successful inbound ENROLL automatically refreshes
 // wg-go's peer list when the host tunnel is currently UP.
 // Idempotent — the hub just stores the reference.
 hub.hostReconfigurer = this

 // Load synchronously: tunnels.json is a small file (one JSON
 // blob, kilobytes at most) and downstream code paths
 // (renameTunnel, ACTION_RENAME_TUNNEL etc.) assume the list is
 // populated by the time MainActivity's first composition runs.
 // The async-launch pattern here previously raced with the
 // intent-driven rename hook used by the E2E test.
 _tunnels.value = hub.loadTunnels()
 // HostModeBackend is an Application-scoped singleton kept
 // alive by the OFFER-listener foreground service; it can
 // outlive the Activity (and therefore this ViewModel). If
 // the user leaves and re-enters the app while a host tunnel
 // is up, the previous ViewModel is gone but the runner is
 // still serving traffic — reconcile so the UI reflects the
 // real state instead of showing the tunnel as Idle (which
 // then prompts the user to tap Connect and earns them an
 // "another tunnel is already running" error from
 // HostModeBackend.start). The unified [activeTunnelIds] flow
 // already mirrors the backend's set (the StateFlow combine
 // picks up `hostModeBackend.activeTunnelIds.value` on
 // construction), so we just need to (a) bring `_liveState`
 // out of "DOWN" if anything is up, and (b) restart the
 // throughput sampler so the detail screen has stats to
 // display. Joiner-side recovery is a separate problem — the
 // bound JoinerVpnService is per-Context, so a new Activity
 // always starts unbound.
 if (WgrtcApp.instance.hostModeBackend.activeTunnelIds.value.isNotEmpty()) {
 _liveState.value = "UP"
 startThroughputSampler()
 }
 // Subscribe to the hub's endpoint-applied events so the
 // viewmodel's _tunnels stays in sync with the disk state
 // when listeners (which run in the hub's scope) rewrite
 // tunnels.json behind our back.
 viewModelScope.launch {
 hub.endpointUpdates.collect { evt ->
 _tunnels.value = _tunnels.value.map {
 if (it.id == evt.tunnelId) evt.tunnel else it
 }
 // If this tunnel is currently UP, push the new
 // endpoint into the kernel so the live handshake
 // follows the daemon's roam. Done here (not in
 // the hub) because the hub is Application-scoped
 // and shouldn't depend on the wireguard backend's
 // setState. The hub already saved the new
 // configText to disk; here we just re-apply it.
 if (_activeJoinerTunnelId.value == evt.tunnelId) {
 reconfiguringTunnelId = evt.tunnelId
 try {
 // Live endpoint update: route through the
 // joiner service's in-place UAPI reconfigure.
 // Host tunnels never have their Endpoint =
 // line rewritten by the listener, so this is
 // only load-bearing for joiner-side roam.
 activeJoinerBinding?.service?.let { svc ->
 withContext(Dispatchers.IO) {
 svc.reconfigure(evt.tunnel.configText)
 }
 }
 } catch (t: Throwable) {
 Log.w("wgrtc-vm",
 "live reconfigure after endpoint update failed", t)
 } finally {
 reconfiguringTunnelId = null
 }
 } else if (_activeJoinerNTunnelIds.value.contains(evt.tunnelId)) {
 // Joiner-N parallel of the single-joiner reconfigure
 // above. JoinerNVpnService.reconfigure takes the
 // tunnel id and the rendered UAPI; the shared stack
 // re-applies it against the per-slot bridge handle
 // without rebuilding routes.
 reconfiguringTunnelId = evt.tunnelId
 try {
 activeJoinerNBinding?.service?.let { svc ->
 withContext(Dispatchers.IO) {
 svc.reconfigure(
 evt.tunnelId,
 WgQuickUapi.render(evt.tunnel.configText),
 )
 }
 }
 } catch (t: Throwable) {
 Log.w("wgrtc-vm",
 "joiner-N reconfigure after endpoint update failed",
 t)
 } finally {
 reconfiguringTunnelId = null
 }
 }
 }
 }
 }

 fun clearError() { _lastError.value = null }

 // ---------------------------------------------------------------- CRUD

 fun deleteTunnel(id: String) {
 viewModelScope.launch {
 if (activeTunnelIds.value.contains(id)) disconnect(id)
 hub.stop(id)
 val updated = _tunnels.value.filterNot { it.id == id }
 _tunnels.value = updated
 withContext(Dispatchers.IO) { hub.saveTunnels(updated) }
 // drop cached per-tunnel flows so a long-lived
 // process with many rename/delete cycles can't grow the
 // caches unboundedly.  Each StateFlow was rooted in
 // viewModelScope; without eviction those subscriptions
 // outlive the tunnel even with WhileSubscribed, because the
 // map still holds the StateFlow object (and the
 // grace-window timer would never see a re-subscribe).
 pruneTunnelCaches(id)
 }
 }

 /** Evict the per-tunnel cache entries for [tunnelId].  Called by
 * [deleteTunnel] and exposed package-private for unit tests of
 * the leak-fix contract.  The sampler's writes into
 * [_throughput] / [_peerStats] for a still-active tunnel keep
 * working; they just don't get reflected through a cached
 * StateFlow until the next subscriber pulls a fresh one.  Safe
 * to call for an id that was never cached (no-op). */
 internal fun pruneTunnelCaches(tunnelId: String) {
 isActiveCache.remove(tunnelId)
 throughputCache.remove(tunnelId)
 peerStatsCache.remove(tunnelId)
 }

 // ─── OFFER listener lifecycle moved to ListenerHub ────────────
 // The Application-scoped hub owns the listeners now (see
 // data/ListenerHub.kt and OfferListenerService). Anything the
 // ViewModel needs to do that touched listeners directly should
 // delegate to `hub` instead.

 /**
 * Rename an existing tunnel. Preserves [Tunnel.id] (so VPN
 * consent persists, the active-tunnel pointer doesn't reset, etc.)
 * and updates only the user-visible name. Trimmed. Empty-name
 * input is rejected silently — callers should validate first.
 *
 * Returns the updated [Tunnel] or null if no tunnel matched [id]
 * or the new name was blank.
 */
 fun renameTunnel(id: String, newName: String): Tunnel? {
 val trimmed = newName.trim()
 if (trimmed.isEmpty()) return null
 val tunnels = _tunnels.value
 val current = tunnels.firstOrNull { it.id == id } ?: return null
 if (current.name == trimmed) return current
 val updated = tunnels.map { if (it.id == id) it.copy(name = trimmed) else it }
 _tunnels.value = updated
 viewModelScope.launch(Dispatchers.IO) { hub.saveTunnels(updated) }
 return updated.first { it.id == id }
 }

 /**
 * Apply a full edit to an existing tunnel. Disconnects first if
 * the tunnel is active (the wg-quick config is about to change
 * underneath wg-go; safer to bring it down cleanly), validates the
 * new wg-quick text, persists, and reconciles the OFFER-listener
 * subscription so a changed broker rebinds. Returns true on
 * success; on failure sets [lastError] and returns false (the
 * previous tunnel stays in place).
 *
 * The caller passes a fully-formed [Tunnel] — typically a
 * `current.copy(...)` with the changed fields. Callers that only
 * want to rename should keep using [renameTunnel] — it skips the
 * disconnect + reconcile dance.
 */
 suspend fun updateTunnel(updated: Tunnel): Boolean {
 // Validate config text up front — abort cleanly if the user
 // pasted broken text rather than partially apply.
 try {
 WgQuickUapi.render(updated.configText)
 } catch (t: Throwable) {
 _lastError.value = "Configuration didn't parse: ${t.message ?: "unknown error"}"
 return false
 }
 // Bring the tunnel down if it's currently up — wg-go can't
 // hot-swap config, and even if it could the OFFER listener's
 // candidate cache may now be stale (broker change).
 if (activeTunnelIds.value.contains(updated.id)) {
 disconnect(updated.id)
 }
 // Listener subscription depends on the broker; tear down the
 // old one before we save so reconcileFromStore picks up the
 // new coordinates cleanly.
 hub.stop(updated.id)
 val all = _tunnels.value.map {
 if (it.id == updated.id) updated else it
 }
 _tunnels.value = all
 withContext(Dispatchers.IO) { hub.saveTunnels(all) }
 // Re-attach listener with the new config (handles broker swap,
 // salt rotation, source change all in one place).
 hub.reconcileFromStore()
 WgrtcApp.instance.ensureListenerServiceRunning()
 return true
 }

 /** Add a tunnel from raw wg-quick text. Throws on parse failure. */
 fun addLegacyTunnel(name: String, configText: String, source: Tunnel.Source = Tunnel.Source.LEGACY): Tunnel {
 WgQuickUapi.render(configText) // validate
 val t = Tunnel(name = name.ifBlank { defaultName() }, configText = configText, source = source)
 persistAndStart(t)
 return t
 }

 /**
 * : add a host-mode tunnel. Generates a fresh keypair +
 * salt via [HostModeFactory], persists, and starts the host-mode
 * listener. Returns the freshly-minted [Tunnel].
 *
 * The persisted tunnel is immediately usable: the user can call
 * [mintHostEnrollToken] on it to issue a QR voucher; the listener
 * (via the hub's reconcileFromStore semantics) will accept
 * inbound ENROLL requests as soon as the host-mode listener
 * comes online.
 */
 fun addHostModeTunnel(
 name: String,
 subnet: String,
 hostIp: String,
 listenPort: Int,
 brokerWss: String,
 brokerKey: String,
 advertisedAllowedIps: String? = null,
 ): Tunnel {
 // Canonicalize before persisting so legacy whitespace
 // from defaults or user input never survives onto disk.
 // See WgAllowedIps for the ChromeOS compat constraint.
 val canonAllowed = advertisedAllowedIps?.let {
 WgAllowedIps.canonicalize(it)
 }?.ifBlank { null }
 val t = HostModeFactory.newTunnel(
 name = name.ifBlank { defaultName() },
 subnet = subnet,
 hostIp = hostIp,
 listenPort = listenPort,
 brokerWss = brokerWss,
 brokerKey = brokerKey,
 advertisedAllowedIps = canonAllowed,
 )
 persistAndStart(t)
 return t
 }

 /**
 * : mint a fresh enrollment token for [tunnelId] (a
 * host-mode tunnel) and return the wgrtc-enroll URI as a string
 * for QR / clipboard rendering. Returns null if the tunnel
 * doesn't exist, isn't host-mode, or is missing crypto fields.
 */
 fun mintHostEnrollToken(
 tunnelId: String,
 nameHint: String,
 ttlMs: Long = 600_000L,
 ): String? = hub.mintHostEnrollToken(tunnelId, nameHint, ttlMs)

 /**
 * Persist a tunnel produced by the wormhole-code joiner flow
 * ([WormholeJoinController.resultingTunnel]) and start its
 * OFFER listener. Same persist-then-start contract as
 * [addEnrollTunnel] — the broker coordinates carried in [t] let
 * the listener subscribe under the host's routing-id so the
 * joiner picks up endpoint roams without having to re-enroll.
 */
 fun addWormholeJoinedTunnel(t: Tunnel): Tunnel {
 persistAndStart(t)
 return t
 }

 /**
 * Add the joiner returned by a wormhole host session
 * ([WormholeHostController.wormholeResult]) as an enrolled peer
 * of an existing host-mode tunnel. Goes through the same
 * persist-then-reconfig path the QR-enrollment flow uses, so the
 * host's wg-go starts accepting the new peer's handshake the
 * moment this returns.
 */
 /**
 * Revoke an enrolled peer from a host-mode tunnel without
 * tearing the tunnel down for the other peers. Triggers a
 * single DOWN+UP cycle on the host's wg-go (~125 ms blip);
 * other peers reconnect automatically via WG's normal
 * handshake-retry behavior.
 */
 fun revokeEnrolledPeer(tunnelId: String, pubkeyB64: String) {
 viewModelScope.launch {
 try {
 hub.revokeEnrolledPeer(
 tunnelId = tunnelId,
 pubkeyB64 = pubkeyB64,
 reconfigurer = this@WgrtcViewModel,
 )
 _tunnels.value = withContext(Dispatchers.IO) { hub.loadTunnels() }
 } catch (t: Throwable) {
 Log.e("WgrtcVM", "revokeEnrolledPeer failed", t)
 _lastError.value = "Couldn't revoke peer: ${t.message}"
 }
 }
 }

 fun addWormholeEnrolledPeer(result: com.gutschke.wgrtc.data.HostWormholeResult) {
 viewModelScope.launch {
 try {
 hub.applyWormholePeer(result, reconfigurer = this@WgrtcViewModel)
 _tunnels.value = withContext(Dispatchers.IO) { hub.loadTunnels() }
 } catch (t: Throwable) {
 Log.e("WgrtcVM", "addWormholeEnrolledPeer failed", t)
 _lastError.value = "Failed to add peer: ${t.message}"
 }
 }
 }

 // ─── Per-peer last-invitation cache ───────────────────────────────
 //
 // Process-scoped (StateFlow inside the ViewModel — survives
 // configuration changes but not process death). Used by the
 // host-mode peer list to expose a "Show invitation" action that
 // re-opens the manual-config dialog with the wg-quick text we
 // generated when the peer was first enrolled.
 //
 // Why not persistent: persisting joiner private keys on the
 // host's disk is a security smell — the host doesn't actually
 // need to keep them (the joiner has their own copy after
 // import). Process-scoped strikes the right balance: useful
 // while debugging "did this config really work?", expires
 // when the user reboots, never touches durable storage.
 private val _lastInvitations =
 kotlinx.coroutines.flow.MutableStateFlow<Map<String, String>>(emptyMap())
 val lastInvitations: kotlinx.coroutines.flow.StateFlow<Map<String, String>> =
 _lastInvitations

 /** Stash a freshly-generated wg-quick text against the peer it
 * was minted for. Called from the manual-config + wormhole
 * paths. Overwrites any previous entry for the same pubkey. */
 fun rememberInvitation(peerPubkeyB64: String, wgQuickText: String) {
 _lastInvitations.value = _lastInvitations.value + (peerPubkeyB64 to wgQuickText)
 }

 /** Add an ENROLL-source tunnel, retaining the broker coordinates
 * needed for the [OfferListener]. See [Tunnel.brokerWss] etc. */
 private fun addEnrollTunnel(name: String, configText: String, uri: EnrollUri): Tunnel {
 WgQuickUapi.render(configText) // validate
 val saltB64Url = JBase64.getUrlEncoder().withoutPadding().encodeToString(uri.salt)
 val t = Tunnel(
 name = name.ifBlank { defaultName() },
 configText = configText,
 source = Tunnel.Source.ENROLL,
 brokerWss = uri.brokerWss,
 brokerKey = uri.brokerKey,
 saltB64 = saltB64Url,
 )
 persistAndStart(t)
 return t
 }

 /** Common path for adding either flavor: append, persist, and
 * fire up the OFFER listener if the tunnel has the broker
 * coordinates needed for it. */
 private fun persistAndStart(t: Tunnel) {
 viewModelScope.launch {
 val updated = _tunnels.value + t
 _tunnels.value = updated
 withContext(Dispatchers.IO) { hub.saveTunnels(updated) }
 when (t.source) {
 Tunnel.Source.ENROLL -> {
 hub.start(t)
 WgrtcApp.instance.ensureListenerServiceRunning()
 }
 Tunnel.Source.HOST_MODE -> {
 // host: register the inbound-ENROLL
 // listener so any client scanning a token URI
 // (mintHostEnrollToken) reaches a live broker
 // session. Foreground service makes sure the
 // listener survives activity destruction.
 hub.startHostMode(t)
 WgrtcApp.instance.ensureListenerServiceRunning()
 }
 else -> { /* LEGACY / MANUAL — no listener needed */ }
 }
 }
 }

 /**
 * Run a single ENROLL round-trip and persist the resulting tunnel.
 * Returns the new Tunnel on success, or throws with a human message
 * (also stored in [lastError]) on failure.
 */
 suspend fun enrollAndAdd(uri: EnrollUri, deviceLabel: String, name: String?): Tunnel {
 // Each fresh attempt starts with a clean error label — otherwise
 // "timeout" or "decryption failed" from an earlier failed run
 // sticks around in the UI even after a later attempt succeeds.
 _lastError.value = null
 val client = EnrollClient(deviceLabel = deviceLabel)
 return when (val r = withContext(Dispatchers.IO) { client.enroll(uri, deviceLabel) }) {
 is EnrollResult.Ok -> {
 val cfgText = renderEnrollConfig(uri, r)
 val tunnelName = name?.ifBlank { null } ?: uri.serverName ?: defaultName()
 val tunnel = addEnrollTunnel(tunnelName, cfgText, uri)
 // Seed the candidate cache from the daemon's
 // ENROLL_OK response so the very first Connect races
 // the full ranked list (LAN ahead of public, etc.)
 // without waiting for a daemon OFFER — the daemon
 // doesn't send OFFERs to peers that are already UP,
 // so without this seed an enrolled-and-connected
 // tunnel would never get a fresh candidate list.
 val seed = r.plaintext.candidates.orEmpty().map {
 com.gutschke.wgrtc.signalling.EndpointUpdate(
 ip = it.ip, port = it.port,
 ts = r.plaintext.timestamp,
 )
 }
 hub.seedCandidates(tunnel.id, seed)
 tunnel
 }
 is EnrollResult.Err -> {
 val msg = "server rejected (${r.plaintext.code})" +
 (r.plaintext.note?.let { ": $it" } ?: "")
 if (r.plaintext.code == "TOKEN_USED") {
 // Promote this specific code to the prominent
 // banner — the user must notice it. The
 // authenticated TOKEN_USED can only come from a
 // race-loss (legit user enrolled second after
 // a leaked QR) or from a re-use of a consumed
 // token; both are worth telling the user about
 // out loud.
 _tokenUsedAlert.value = TokenUsedAlert(serverNote = r.plaintext.note)
 }
 _lastError.value = msg
 throw IllegalStateException(msg)
 }
 is EnrollResult.Failed -> {
 val msg = "enrollment failed: ${r.reason}"
 _lastError.value = msg
 throw IllegalStateException(msg)
 }
 }
 }

 /**
 * The fallback name [addLegacyTunnel] / [enrollAndAdd] would give
 * a tunnel if the caller passed an empty name. Public so the add
 * screens can show it as a placeholder ("leave blank → tunnel-N").
 */
 fun defaultName(): String {
 val n = _tunnels.value.size + 1
 return "tunnel-$n"
 }

 // ---------------------------------------------------------- Connect/Disconnect

 /**
 * Send a `signal_wake` to every ENROLL-source tunnel. Hub
 * debounces per-tunnel, so this is cheap even when called on every
 * onResume. Use to refresh stale endpoints before the user
 * decides to tap Connect — saves up to ~30 s of waiting on the
 * daemon's poll cycle if the server has roamed since we last
 * heard from it.
 */
 fun wakeAllEnrollTunnels() {
 for (t in _tunnels.value) {
 if (t.source == Tunnel.Source.ENROLL) hub.wake(t.id)
 }
 }

 /** Parse the `Endpoint = <host>:<port>` line from a wg-quick
 * config block. Returns an [EndpointUpdate] only when the host
 * is a literal IPv4 / IPv6 address — hostnames return null, the
 * caller falls back to wg-tunnel's hostname resolution.
 * helper. */
 private fun parseLiteralEndpointAsCandidate(configText: String): EndpointUpdate? {
 for (line in configText.lines()) {
 val trimmed = line.trim()
 if (!trimmed.startsWith("Endpoint", ignoreCase = true)) continue
 if (!trimmed.contains("=")) continue
 val rhs = trimmed.substringAfter("=").trim()
 // Strip a trailing port; keep IPv6 literals' [brackets].
 val lastColon = rhs.lastIndexOf(":")
 if (lastColon < 0) continue
 val host = rhs.substring(0, lastColon).trim()
 .removeSurrounding("[", "]")
 val port = rhs.substring(lastColon + 1).trim().toIntOrNull()
 ?: continue
 // Literal-only check — getByName would resolve a hostname,
 // which we don't want at this stage (the legacy fallback
 // path handles hostnames via Config.parse). Mirror the
 // IP_LITERAL regex from signalling/Cidr.kt.
 if (!Regex("""^(\d{1,3}(\.\d{1,3}){3}|[0-9a-fA-F:]+)$""").matches(host)) {
 return null
 }
 return EndpointUpdate(
 ip = host, port = port,
 ts = System.currentTimeMillis() / 1000,
 )
 }
 return null
 }

 /**
 * The tunnels currently considered "active" for the purposes of the
 * AllowedIPs overlap gate.  Reads the unified [activeTunnelIds]
 * directly — it already encodes the union of the joiner slot
 * ([_activeJoinerTunnelId]) and the host slot map
 * ([HostModeBackend.activeTunnelIds], N entries).
 */
 private fun activeTunnelsForOverlapGate(): List<Tunnel> {
 val byId = _tunnels.value.associateBy { it.id }
 val ids = try {
 activeTunnelIds.value
 } catch (_: Throwable) {
 // WgrtcApp not initialised yet (unit-test seam) — treat as
 // no active tunnel.
 emptySet()
 }
 return ids.mapNotNull { byId[it] }
 }

 /** Bring this tunnel UP after VPN consent has already been granted by the caller.
 *
 * Step F.3: when the listener has cached a multi-candidate OFFER
 * for this tunnel, run the [ConnectionRunner] race
 * (probe-filter + same-subnet override + per-candidate handshake
 * timeout). When no candidate list is available (legacy tunnel,
 * listener not yet running, no OFFER seen), fall back to the
 * pre-Step-F single-setState(UP) path with the persisted
 * Endpoint = line. Both paths fire a signal_wake first so the
 * listener has a chance to refresh stale endpoints.
 *
 * registers `coroutineContext[Job]` as [connectJob] so
 * [disconnect] can `cancelAndJoin` an in-flight connect — without
 * that, Disconnect during the race interleaves with the next
 * setEndpoint and the user sees the tunnel come back up. */
 suspend fun connect(id: String) {
 // Register this coroutine as the active connect job for [id];
 // cleared on exit (success or failure) so the next disconnect
 // doesn't try to cancel a finished job, and keyed by tunnel
 // id so a disconnect on one tunnel never cancels another's
 // in-flight connect.
 currentCoroutineContext()[Job]?.let { connectJobs[id] = it }
 // Mark the tunnel as "connecting" immediately so the UI can
 // show a per-row spinner. Cleared in the finally block at
 // the bottom of this function.
 _connectingTunnelId.value = id
 val t = _tunnels.value.firstOrNull { it.id == id }
 ?: error("no tunnel with id $id")
 // ─── AllowedIPs overlap gate ─────────────────────────────
 // Refuse to bring up a tunnel whose claimed CIDR ranges
 // overlap any tunnel that's already active.  Today the host +
 // joiner single-instance checks fire first so this is mostly
 // dormant, but the wiring is in place for when those
 // restrictions come out (task D4).  See [TunnelOverlapGuard].
 val activeForGate = activeTunnelsForOverlapGate()
 val conflict = com.gutschke.wgrtc.data.TunnelOverlapGuard
 .firstOverlap(t, activeForGate)
 if (conflict != null) {
 val msg = "Can't bring up \"${t.name}\" — its address range " +
 "overlaps the active tunnel \"${conflict.name}\". " +
 "Disconnect that one first or change AllowedIPs."
 Log.w("wgrtc-vm", msg)
 _lastError.value = msg
 _connectingTunnelId.value = null
 val myJob = currentCoroutineContext()[Job]
 connectJobs.compute(id) { _, v -> if (v == myJob) null else v }
 throw IllegalStateException(msg)
 }
 // ─── Host () short-circuit ────────────────────────
 // Host-mode tunnels run on wgbridge_native's gvisor netstack.
 // There's no candidate race for a host (no daemon-driven
 // OFFERs to wait for) and no DOWN→UP cycle on revoke
 // (IpcSet handles in-place reconfigure).
 if (t.source == Tunnel.Source.HOST_MODE) {
 try {
 WgrtcApp.instance.hostModeBackend.start(t)
 // The backend's [activeTunnelIds] now contains this id;
 // [activeTunnelIds] (the unified flow on this VM)
 // mirrors it automatically.  We only need to nudge
 // `_liveState` and the per-tunnel sampler.
 _liveState.value = "UP"
 _lastError.value = null
 startThroughputSampler()
 Log.i("wgrtc-vm", "connect: host tunnel $id is up")
 } catch (e: com.gutschke.wgrtc.data.PortCollisionException) {
 Log.w("wgrtc-vm", "host start refused: port collision", e)
 // resolve the other tunnel's id to its display
 // name so the snackbar is human-readable.  Falls back
 // to the raw id if the tunnel was deleted between the
 // collision check and the catch.
 val otherName = _tunnels.value
 .firstOrNull { it.id == e.existingTunnelId }
 ?.name ?: e.existingTunnelId
 _lastError.value = "Can't start \"${t.name}\" — UDP port " +
 "${e.port} is already used by \"$otherName\". " +
 "Disconnect that tunnel or pick a different ListenPort."
 throw e
 } catch (e: Throwable) {
 Log.e("wgrtc-vm", "host start failed", e)
 // Don't touch `_liveState` here — other tunnels may be
 // up (since D4.H1) and a global "DOWN" would mislead
 // the UI.  The unified set already excludes this id
 // because the backend's start() didn't add it.
 _lastError.value = "Host start failed: ${e.message}"
 throw e
 } finally {
 if (_connectingTunnelId.value == id) _connectingTunnelId.value = null
 val myJob = currentCoroutineContext()[Job]
 connectJobs.compute(id) { _, v -> if (v == myJob) null else v }
 }
 return
 }
 // Fire a signal_wake before we ask the kernel to bring the tunnel
 // UP — if the daemon's stored Endpoint is stale the wake produces
 // a fresh OFFER (with current STUN-discovered IP) within ~1 s,
 // and the listener will rewrite our `Endpoint = …` line before
 // the first kernel handshake retry. Fire-and-forget; the worst
 // case is the kernel uses the stored endpoint and we wait the
 // usual handshake retry for the listener-driven update. Hub
 // debounces, so this is safe to spam.
 hub.wake(id)
 try {
 // cached candidates may be stale (last OFFER from
 // hours ago — STUN IP may have rotated). We just fired a
 // wake; give the listener up to FRESH_OFFER_WAIT_MS to
 // catch the daemon's response before we commit to the
 // cached list. Skip the wait if the cache is already
 // recent enough (FRESH_OFFER_THRESHOLD_MS).
 val initialCached = hub.latestCandidates(id)
 val initialAge = hub.candidateAgeMs(id) ?: Long.MAX_VALUE
 val cached: List<EndpointUpdate> =
 if (initialCached.isNotEmpty() && initialAge < FRESH_OFFER_THRESHOLD_MS) {
 initialCached
 } else {
 val refreshed = withTimeoutOrNull(FRESH_OFFER_WAIT_MS) {
 hub.candidateRefresh.filter { it == id }.first()
 hub.latestCandidates(id)
 }
 refreshed ?: initialCached
 }
 // Build the candidate list to race. Three cases:
 // 1. Listener has cached a multi-candidate OFFER → use it.
 // 2. No cached OFFER, but persisted Endpoint is a literal
 // IP → synthesise a single-element list so the
 // picker / probe / strict-hotspot logic still runs.
 // 3. Persisted Endpoint is a hostname → bypass the runner
 // (Config.parse handles hostname resolution) and use
 // the legacy single-setState(UP) path. Hostnames are
 // uncommon for ENROLL tunnels but legal for LEGACY.
 val candidates: List<EndpointUpdate> = when {
 cached.isNotEmpty() -> cached
 else -> parseLiteralEndpointAsCandidate(t.configText)?.let { listOf(it) }
 ?: emptyList()
 }
 Log.i("wgrtc-vm",
 "connect($id): cache=${initialCached.size}entries " +
 "(age=${if (initialAge == Long.MAX_VALUE) "n/a" else "${initialAge}ms"}), " +
 "after-wait=${cached.size}entries, " +
 "racing=${candidates.size}: ${candidates.joinToString(",") { "${it.ip}:${it.port}" }}")
 if (candidates.isNotEmpty()) {
 if (WgrtcApp.instance.settings.joinerNEnabled) {
 // Joiner-N path: share one VpnService across N
 // joiners via the userspace gvisor netstack. The
 // shared binding is cached on the ViewModel; the
 // first joiner triggers Builder.establish, every
 // subsequent join re-establishes against the
 // wider union of addresses + routes.
 connectViaJoinerN(id, t, candidates)
 return
 }
 // Joiner path: bind JoinerVpnService and run the
 // candidate race against wgbridge_native in TUN-fd
 // mode. After the legacy wireguard-android
 // path is gone, so there is no backend selection.
 val app = getApplication<android.app.Application>()
 .applicationContext
 val binding = bindJoinerVpnService(app)
 val parsed = try { JoinerVpnConfig.parse(t.configText) }
 catch (e: Throwable) {
 binding.unbind()
 throw e
 }
 val recfg = try { binding.service.start(parsed, t.configText) }
 catch (e: Throwable) {
 binding.unbind()
 throw e
 }
 activeJoinerBinding = binding
 Log.i("wgrtc-vm", "connect: joiner bound + started for $id")
 val controller: com.gutschke.wgrtc.signalling
 .TunnelEndpointController = WgBridgeTunnelEndpointController(recfg, hub)
 // the JoinerVpnService is now up, which means *this*
 // process's default network is the VPN tun. The tun has only
 // the joiner's v4 /32 address (from `[Interface] Address`),
 // so any v6 candidate probe fails source-address selection
 // with ENETUNREACH before a packet even leaves the kernel.
 // Route the probe through VpnService.protect() so it uses
 // the underlying WiFi/cellular network, which is typically
 // dual-stack.
 val joinerService = binding.service
 val probe = com.gutschke.wgrtc.signalling.RealUdpProbe(
 protector = com.gutschke.wgrtc.signalling.SocketProtector {
 s -> joinerService.protect(s)
 },
 )
 val runner = ConnectionRunner(controller, probe = probe)
 val ifaces = withContext(Dispatchers.IO) { enumerateLocalInterfaces() }
 // strictHotspot=false: picker returns same-subnet
 // candidates first, then non-same-subnet — runner races
 // them in order, so LAN gets tried before public.
 // Falling through to public IS allowed when LAN
 // demonstrably fails (handshake didn't complete) —
 // user explicitly asked for "prefer LAN, fall back to
 // public if needed" rather than "LAN only".
 //
 // strictHotspot=true is reserved for the phone-hosts-
 // hotspot scenario, where fallback to public goes
 // through the carrier and burns mobile data. That
 // path doesn't apply here (the phone is a CLIENT, not
 // hosting a hotspot for the server).
 val r = runner.connect(
 tunnelId = id,
 candidates = candidates,
 localInterfaces = ifaces,
 strictHotspot = false,
 // Cold-start: the runner was JUST opened by
 // binding.service.start above. Any handshake on
 // this controller IS the fresh one — pre-race
 // should not need to beat a prior baseline. Fixes
 // PS27 where a fast-path handshake (e.g. ARC
 // loopback v6, 4 ms) completed before runner
 // .connect started polling, leaving the capture-
 // at-entry baseline equal to the just-completed
 // handshake and pre-race sitting out its full
 // 2.5 s budget for a successor that never comes.
 baselineHandshakeMs = 0L,
 )
 when (r) {
 is ConnectAttemptResult.Success -> {
 Log.i("wgrtc-vm",
 "connect: race succeeded on " +
 "${r.finalEndpoint.ip}:${r.finalEndpoint.port} " +
 "(egress=${r.egressInterface ?: "default"}, " +
 "wait=${r.handshakeWaitMs}ms)")
 _activeJoinerTunnelId.value = id
 // Without this the UI's TunnelDetailScreen falls
 // through to its `isUp && liveState != "UP"`
 // arm and shows the "connecting" spinner
 // forever even though the WG handshake is
 // already complete. Mirrors the host-mode
 // success path above.
 _liveState.value = "UP"
 _liveEndpoints.value = _liveEndpoints.value + (id to r.finalEndpoint)
 _lastError.value = null
 // The race controller persisted the new
 // endpoint via hub.rewriteEndpoint, but that
 // path intentionally doesn't fire
 // endpointUpdates (its contract is "listener
 // saw new endpoint", not race-driven). Refresh
 // _tunnels from disk so the UI reflects the
 // race winner — otherwise the persisted config
 // updates but the screen keeps showing the
 // pre-connect endpoint (e.g. the embedded
 // public IP after the race picked LAN).
 _tunnels.value = withContext(Dispatchers.IO) { hub.loadTunnels() }
 startThroughputSampler()
 networkChangeMonitor.start()
 // hand the live controller + runner
 // off to a RoamController so subsequent
 // network changes can re-race in-place
 // (the existing networkChangeMonitor wake
 // alone refreshes the listener's candidate
 // cache but never pushes a new endpoint
 // into wireguard-go).
 activeRoamController?.stop()
 activeRoamController =
 com.gutschke.wgrtc.signalling.RoamController(
 tunnelId = id,
 controller = controller,
 runner = runner,
 candidateProvider = {
 val cached = hub.latestCandidates(id)
 if (cached.isNotEmpty()) cached
 else parseLiteralEndpointAsCandidate(
 _tunnels.value
 .firstOrNull { it.id == id }
 ?.configText ?: t.configText
 )?.let { listOf(it) } ?: emptyList()
 },
 ifaceProvider = {
 withContext(Dispatchers.IO) {
 enumerateLocalInterfaces()
 }
 },
 scope = viewModelScope,
 onResult = { result ->
 when (result) {
 is ConnectAttemptResult.Success -> {
 Log.i("wgrtc-vm",
 "roam: re-race succeeded on " +
 "${result.finalEndpoint.ip}:" +
 "${result.finalEndpoint.port} " +
 "(egress=${result.egressInterface
 ?: "default"})")
 _liveEndpoints.value =
 _liveEndpoints.value +
 (id to result.finalEndpoint)
 }
 is ConnectAttemptResult.Failed ->
 Log.w("wgrtc-vm",
 "roam: re-race failed (${result.reason})")
 }
 },
 logger = com.gutschke.wgrtc.signalling.RoamLogger { level, msg ->
 when (level) {
 'W' -> Log.w("wgrtc-roam", msg)
 'D' -> Log.d("wgrtc-roam", msg)
 else -> Log.i("wgrtc-roam", msg)
 }
 },
 ).also { it.startPolling() }
 return
 }
 is ConnectAttemptResult.Failed -> {
 // Distinguish three failure shapes so the user
 // knows what's actionable:
 // - strict-mode blocked WITH a public
 // fallback that exists (real hotspot
 // refusal — re-try elsewhere or relax
 // strict mode).
 // - strict-mode blocked but only one
 // same-subnet candidate existed at all
 // (no fallback was even available — the
 // server probably moved subnet, re-enroll).
 // - generic exhaustion (all candidates
 // timed out or were unreachable).
 val tried = r.triedCandidates.size
 val msg = when {
 r.strictModeBlocked && tried > 1 ->
 "Local connection failed (strict-hotspot " +
 "mode refused to fall back to public IP)"
 r.strictModeBlocked ->
 "Local connection failed: server's LAN " +
 "address is unreachable from this " +
 "network. Re-scan the QR if you're on a " +
 "different network now."
 else -> "All $tried candidate(s) failed: ${r.reason}"
 }
 Log.w("wgrtc-vm", "connect race failed: $msg")
 _lastError.value = msg
 _activeJoinerTunnelId.value = null
 // Clean up the joiner-vpn-service binding (if
 // any) — controller.bringDown closes the
 // runner but doesn't unbind the service.
 activeJoinerBinding?.let {
 try { it.service.stop() } catch (_: Throwable) {}
 it.unbind()
 activeJoinerBinding = null
 }
 throw RuntimeException(msg)
 }
 }
 }
 if (WgrtcApp.instance.settings.joinerNEnabled) {
 connectViaJoinerNNoCandidates(id, t)
 return
 }
 // No-candidates fallback: bring the joiner up directly via
 // wgbridge_native with the persisted wg-quick text. The
 // peer's `Endpoint = host:port` (or `ip:port`) is forwarded
 // verbatim into IpcSet; wireguard-go resolves hostnames
 // internally. The OFFER listener will rewrite the
 // persisted config to a literal IP on first OFFER, after
 // which the candidate-race path takes over.
 val app = getApplication<android.app.Application>()
 .applicationContext
 val binding = bindJoinerVpnService(app)
 val parsed = try { JoinerVpnConfig.parse(t.configText) }
 catch (e: Throwable) { binding.unbind(); throw e }
 try { binding.service.start(parsed, t.configText) }
 catch (e: Throwable) { binding.unbind(); throw e }
 activeJoinerBinding = binding
 _activeJoinerTunnelId.value = id
 _liveState.value = "UP"
 _lastError.value = null
 startThroughputSampler()
 networkChangeMonitor.start()
 } catch (t: kotlinx.coroutines.CancellationException) {
 // Cooperative cancellation (disconnect or G-cancel restart).
 // Don't log as error — the caller knows.
 throw t
 } catch (t: Throwable) {
 Log.e("wgrtc-vm", "connect failed", t)
 _lastError.value = t.message ?: t.javaClass.simpleName
 _activeJoinerTunnelId.value = null
 // stop the network monitor on failure too — without
 // this, an earlier successful connect's monitor stays
 // registered firing wakes for a joiner that's now null.
 // Idempotent.
 networkChangeMonitor.stop()
 activeRoamController?.stop()
 activeRoamController = null
 throw t
 } finally {
 // Only clear if WE are still the registered job (not a
 // later connect that overtook us).
 val myJob = currentCoroutineContext()[Job]
 connectJobs.compute(id) { _, v -> if (v == myJob) null else v }
 // Same guard for the connecting indicator: don't clear
 // a different tunnel's pending connect.
 if (_connectingTunnelId.value == id) _connectingTunnelId.value = null
 }
 }

 /**
 * Per-tunnel disconnect.  Pauses the host slot or tears down the
 * joiner binding for [tunnelId] only; other host tunnels keep
 * running.  Safe to call for an id that isn't actually up
 * (idempotent no-op).
 *
 * UI callers (the per-row Disconnect button, the Disconnect button
 * on TunnelDetailScreen) should always use this.  The whole-app
 * sweep lives on [disconnectAll].
 */
 suspend fun disconnect(tunnelId: String) {
 val hostBackend = WgrtcApp.instance.hostModeBackend
 val isJoiner = _activeJoinerTunnelId.value == tunnelId
 val isJoinerN = _activeJoinerNTunnelIds.value.contains(tunnelId)
 val isHost = hostBackend.activeTunnelIds.value.contains(tunnelId)
 if (!isJoiner && !isJoinerN && !isHost) {
 Log.i("wgrtc-vm", "disconnect($tunnelId): not active, no-op")
 return
 }
 if (isJoiner) {
 // Cancel any in-flight connect race so disconnect's
 // tear-down is the LAST backend mutation, not racing
 // the next setEndpoint of an unfinished candidate sweep.
 // cancelAndJoin waits for the cancellation to settle —
 // ConnectionRunner's delay() / setState calls are
 // cooperatively cancellable.
 tearDownJoinerInternal()
 }
 if (isJoinerN) {
 // Same cancel-then-teardown ordering for the joiner-N
 // path. The helper handles the empty-set collapse so
 // the kernel TUN comes down with the last joiner.
 tearDownJoinerNInternal(tunnelId)
 }
 if (isHost) {
 // Host-side per-tunnel "pause not teardown" — leaves
 // the wireguard-go device alive so a subsequent
 // [connect] is a fast resume instead of a full
 // close+reopen JNI cycle.  [disconnectAll]
 // bypasses this path and calls
 // [HostModeBackend.teardownAll] instead.
 try { hostBackend.stop(tunnelId) }
 catch (t: Throwable) {
 Log.e("wgrtc-vm", "host stop $tunnelId failed", t)
 }
 _throughput.update { it - tunnelId }
 _peerStats.update { it - tunnelId }
 }
 // [_liveState] is a legacy single-tunnel signal; collapse to
 // DOWN only when nothing is left up.  The unified
 // [activeTunnelIds] is the actual source of truth for the
 // UI's per-tunnel badge.
 if (activeTunnelIds.value.isEmpty()) {
 _liveState.value = "DOWN"
 stopThroughputSampler()
 }
 }

 /**
 * Sweep disconnect: stop every running tunnel (joiner + every
 * host slot).  Used by panic / app-exit paths where the JVM is
 * about to lose the process, so JNI resources must actually be
 * released — not just paused.
 *
 * Per-tunnel [disconnect] is the user-facing "pause" path: it
 * calls [HostModeBackend.stop] which suspends the slot but leaves
 * the wireguard-go device alive (the F16 pause-not-close
 * decision, avoids the close+reopen JNI panic that bit us
 * earlier).  That's the right behavior for a user tapping a
 * row's Disconnect, but [disconnectAll] runs at app-exit /
 * panic, so we route the host side through
 * [HostModeBackend.teardownAll] instead — a full close that
 * releases every JNI slot.  The joiner side has no equivalent
 * "pause" so its teardown is the same as the per-tunnel path,
 * factored into [tearDownJoinerInternal] so both callers share
 * one implementation.
 */
 suspend fun disconnectAll() {
 // 1. Joiner first — has a VpnService binding that has to
 //    release before host teardown so HostNativeBackend isn't
 //    racing on the same wireguard-go Device close path.
 if (_activeJoinerTunnelId.value != null) {
 try { tearDownJoinerInternal() }
 catch (t: Throwable) {
 Log.e("wgrtc-vm", "disconnectAll: joiner teardown failed", t)
 }
 }
 // 1b. Joiner-N — drop every joiner from the shared stack;
 //     the last removeJoiner collapses the binding via the
 //     helper's empty-set guard.
 val joinerNSnapshot = _activeJoinerNTunnelIds.value.toList()
 for (id in joinerNSnapshot) {
 try { tearDownJoinerNInternal(id) }
 catch (t: Throwable) {
 Log.e("wgrtc-vm",
 "disconnectAll: joiner-N teardown of $id failed", t)
 }
 }
 // 2. Host slots — full JNI close, not pause.
 try {
 WgrtcApp.instance.hostModeBackend.teardownAll()
 } catch (t: Throwable) {
 Log.e("wgrtc-vm", "disconnectAll: host teardownAll failed", t)
 }
 // 3. State cleanup the same way disconnect() would — once
 //    nothing is left up.  Throughput sampler stops itself
 //    via stopThroughputSampler when both per-tunnel maps go
 //    empty; the sampler also writes empty maps before its
 //    job is canceled, which would wake any per-id throughput
 //    subscribers with null exactly once.
 _throughput.value = emptyMap()
 _peerStats.value = emptyMap()
 if (activeTunnelIds.value.isEmpty()) {
 _liveState.value = "DOWN"
 stopThroughputSampler()
 }
 }

 /** Tear down the joiner slot — cancel the in-flight connect
 * coroutine, stop the network-change monitor + roam controller,
 * stop and unbind the [JoinerVpnService], and clear the active
 * id + this tunnel's stats entries.  Shared between [disconnect]
 * (per-tunnel pause-or-disconnect path) and [disconnectAll]
 * (sweep teardown).  Caller is responsible for the
 * `_liveState`/throughput-sampler collapse afterwards. */
 private suspend fun tearDownJoinerInternal() {
 val joinerId = _activeJoinerTunnelId.value ?: return
 connectJobs.remove(joinerId)?.let {
 try { it.cancelAndJoin() }
 catch (e: Throwable) { Log.w("wgrtc-vm", "connect cancel failed", e) }
 }
 networkChangeMonitor.stop()
 activeRoamController?.stop()
 activeRoamController = null
 activeJoinerBinding?.let { binding ->
 try { binding.service.stop() }
 catch (t: Throwable) {
 Log.e("wgrtc-vm", "joiner stop failed", t)
 }
 binding.unbind()
 activeJoinerBinding = null
 }
 _activeJoinerTunnelId.value = null
 _throughput.update { it - joinerId }
 _peerStats.update { it - joinerId }
 }

 /** Joiner-N candidate-race connect. Mirrors the legacy
  * single-joiner path at the same call-site, but talks to the
  * shared [JoinerNVpnService] instead of [JoinerVpnService]
  * and tracks state in [_activeJoinerNTunnelIds].
  *
  * RoamController is NOT wired into the joiner-N path yet —
  * listener-driven endpoint rewrites still work (via the
  * `endpointUpdates` collector below, which routes through
  * [JoinerNEndpointReconfigurer]), but a mid-tunnel network
  * change won't auto re-race candidates. Acceptable for the
  * opt-in first cut. */
 private suspend fun connectViaJoinerN(
 id: String,
 t: Tunnel,
 candidates: List<EndpointUpdate>,
 ) {
 // Increment BEFORE ensuring the binding, decrement only in
 // finally. Two concurrent connectViaJoinerN calls then can't
 // drop each other's binding through maybeUnbindJoinerN — the
 // helper checks both the active set AND this counter.
 joinerNConnectsInFlight.incrementAndGet()
 try {
 val binding = ensureJoinerNBinding()
 val service = binding.service
 val parsed = try { JoinerVpnConfig.parse(t.configText) }
 catch (e: Throwable) {
 maybeUnbindJoinerN(binding)
 throw e
 }
 val cfg = buildJoinerNConfig(id, t.configText, parsed)
 try {
 withContext(Dispatchers.IO) { service.addJoiner(cfg) }
 } catch (e: Throwable) {
 maybeUnbindJoinerN(binding)
 throw e
 }
 // From this point forward, a failure must call removeJoiner
 // for this id; the helper below collapses the binding when
 // we drop the last joiner.
 val reconfigurer = JoinerNEndpointReconfigurer(service, id)
 val controller: com.gutschke.wgrtc.signalling.TunnelEndpointController =
 WgBridgeTunnelEndpointController(reconfigurer, hub)
 val probe = com.gutschke.wgrtc.signalling.RealUdpProbe(
 protector = com.gutschke.wgrtc.signalling.SocketProtector { s ->
 service.protect(s)
 },
 )
 val runner = ConnectionRunner(controller, probe = probe)
 val ifaces = withContext(Dispatchers.IO) { enumerateLocalInterfaces() }
 val r = runner.connect(
 tunnelId = id,
 candidates = candidates,
 localInterfaces = ifaces,
 strictHotspot = false,
 baselineHandshakeMs = 0L,
 )
 when (r) {
 is ConnectAttemptResult.Success -> {
 Log.i("wgrtc-vm",
 "connect: joiner-N race succeeded on " +
 "${r.finalEndpoint.ip}:${r.finalEndpoint.port} " +
 "(egress=${r.egressInterface ?: "default"}, " +
 "wait=${r.handshakeWaitMs}ms)")
 _activeJoinerNTunnelIds.update { it + id }
 _liveState.value = "UP"
 _liveEndpoints.update { it + (id to r.finalEndpoint) }
 _lastError.value = null
 _tunnels.value = withContext(Dispatchers.IO) { hub.loadTunnels() }
 startThroughputSampler()
 networkChangeMonitor.start()
 // Per-tunnel RoamController.  Mirrors the legacy
 // single-joiner wiring at line ~1200 but the
 // joiner-N path stores one per tunnel id so two
 // joiners on different underlying networks can
 // roam independently.
 activeJoinerNRoamControllers.remove(id)?.stop()
 activeJoinerNRoamControllers[id] =
 com.gutschke.wgrtc.signalling.RoamController(
 tunnelId = id,
 controller = controller,
 runner = runner,
 candidateProvider = {
 val cached = hub.latestCandidates(id)
 if (cached.isNotEmpty()) cached
 else parseLiteralEndpointAsCandidate(
 _tunnels.value
 .firstOrNull { it.id == id }
 ?.configText ?: t.configText
 )?.let { listOf(it) } ?: emptyList()
 },
 ifaceProvider = {
 withContext(Dispatchers.IO) {
 enumerateLocalInterfaces()
 }
 },
 scope = viewModelScope,
 onResult = { result ->
 when (result) {
 is ConnectAttemptResult.Success -> {
 Log.i("wgrtc-vm",
 "roam: joiner-N $id re-race succeeded on " +
 "${result.finalEndpoint.ip}:" +
 "${result.finalEndpoint.port} " +
 "(egress=${result.egressInterface
 ?: "default"})")
 _liveEndpoints.update { ep ->
 ep + (id to result.finalEndpoint)
 }
 }
 is ConnectAttemptResult.Failed ->
 Log.w("wgrtc-vm",
 "roam: joiner-N $id re-race failed " +
 "(${result.reason})")
 }
 },
 logger = com.gutschke.wgrtc.signalling.RoamLogger { level, msg ->
 when (level) {
 'W' -> Log.w("wgrtc-roam", msg)
 'D' -> Log.d("wgrtc-roam", msg)
 else -> Log.i("wgrtc-roam", msg)
 }
 },
 ).also { it.startPolling() }
 }
 is ConnectAttemptResult.Failed -> {
 val tried = r.triedCandidates.size
 val msg = when {
 r.strictModeBlocked && tried > 1 ->
 "Local connection failed (strict-hotspot " +
 "mode refused to fall back to public IP)"
 r.strictModeBlocked ->
 "Local connection failed: server's LAN " +
 "address is unreachable from this network."
 else -> "All $tried candidate(s) failed: ${r.reason}"
 }
 Log.w("wgrtc-vm", "connect race failed (joiner-N): $msg")
 _lastError.value = msg
 try { withContext(Dispatchers.IO) { service.removeJoiner(id) } }
 catch (_: Throwable) {}
 maybeUnbindJoinerN(binding)
 throw RuntimeException(msg)
 }
 }
 } finally {
 joinerNConnectsInFlight.decrementAndGet()
 }
 }

 /** Joiner-N no-candidates fallback — bring the joiner up with
  * the persisted wg-quick text. Mirrors the legacy fallback at
  * the bottom of [connect] but routes through the shared
  * service. */
 private suspend fun connectViaJoinerNNoCandidates(id: String, t: Tunnel) {
 joinerNConnectsInFlight.incrementAndGet()
 try {
 val binding = ensureJoinerNBinding()
 val service = binding.service
 val parsed = try { JoinerVpnConfig.parse(t.configText) }
 catch (e: Throwable) {
 maybeUnbindJoinerN(binding)
 throw e
 }
 val cfg = buildJoinerNConfig(id, t.configText, parsed)
 try {
 withContext(Dispatchers.IO) { service.addJoiner(cfg) }
 } catch (e: Throwable) {
 maybeUnbindJoinerN(binding)
 throw e
 }
 _activeJoinerNTunnelIds.update { it + id }
 _liveState.value = "UP"
 _lastError.value = null
 startThroughputSampler()
 networkChangeMonitor.start()
 } finally {
 joinerNConnectsInFlight.decrementAndGet()
 }
 }

 /** If the joiner-N active set is empty AND no other connect
  * is currently in flight, drop the binding (the shared stack
  * is fully torn down by [JoinerNVpnService.stopAll], but the
  * binding itself still keeps the service process pinned).
  *
  * The in-flight check matters when two concurrent
  * [connectViaJoinerN] calls race: connect A can fail before
  * landing in [_activeJoinerNTunnelIds] (and so the active set
  * is empty from A's perspective), but connect B is still
  * partway through `addJoiner` against the same binding. Without
  * the counter, A would unbind the service while B is mid-JNI.
  *
  * Called only from the error paths in [connectViaJoinerN] /
  * [connectViaJoinerNNoCandidates] — the success-then-disconnect
  * path goes through [tearDownJoinerNInternal] which has its own
  * empty-set guard. */
 private fun maybeUnbindJoinerN(binding: JoinerNVpnBinding) {
 // > 1 because the current caller is itself counted; only
 // drop the binding when WE are the last in-flight connect.
 if (_activeJoinerNTunnelIds.value.isEmpty()
 && joinerNConnectsInFlight.get() <= 1) {
 binding.unbind()
 if (activeJoinerNBinding === binding) {
 activeJoinerNBinding = null
 }
 }
 }

 /** Drop one joiner from the joiner-N shared stack. When the set
  * becomes empty, also stop the service and unbind so the kernel
  * TUN goes away. Mirrors [tearDownJoinerInternal] but for the
  * N-set rather than the single slot. Safe to call for ids not in
  * the set (no-op). Called from [disconnect] when the flag-ON
  * path was used, and from the connect-failure paths below. */
 private suspend fun tearDownJoinerNInternal(tunnelId: String) {
 if (!_activeJoinerNTunnelIds.value.contains(tunnelId)) return
 // Cancel any in-flight connect for THIS id only — the
 // per-tunnel job map means a disconnect on tunnel A never
 // cancels the unrelated in-flight connect of tunnel B
 // (a regression the code-review on commit 1744ea79 caught
 // when connectJob was still a process-wide scalar).
 connectJobs.remove(tunnelId)?.let {
 try { it.cancelAndJoin() }
 catch (e: Throwable) { Log.w("wgrtc-vm", "connect cancel failed", e) }
 }
 // Stop the per-tunnel roam controller before service-side
 // teardown so its in-flight re-race (if any) doesn't see a
 // freshly-removed joiner.
 activeJoinerNRoamControllers.remove(tunnelId)?.stop()
 activeJoinerNBinding?.let { binding ->
 try { withContext(Dispatchers.IO) { binding.service.removeJoiner(tunnelId) } }
 catch (t: Throwable) {
 Log.w("wgrtc-vm", "joiner-N removeJoiner($tunnelId) failed", t)
 }
 }
 _activeJoinerNTunnelIds.update { it - tunnelId }
 _throughput.update { it - tunnelId }
 _peerStats.update { it - tunnelId }
 _liveEndpoints.update { it - tunnelId }
 if (_activeJoinerNTunnelIds.value.isEmpty()) {
 // Only stop the network-change monitor if neither joiner
 // group has anything left. Without this guard, tearing
 // down the last joiner-N tunnel while a legacy single
 // joiner is still up would unsubscribe wakes for the
 // surviving tunnel.
 if (_activeJoinerTunnelId.value == null) {
 networkChangeMonitor.stop()
 }
 activeJoinerNBinding?.let { binding ->
 try { withContext(Dispatchers.IO) { binding.service.stopAll() } }
 catch (t: Throwable) {
 Log.e("wgrtc-vm", "joiner-N stopAll failed", t)
 }
 binding.unbind()
 activeJoinerNBinding = null
 }
 }
 }

 /** Acquire (or reuse) the joiner-N service binding. The shared
  * stack survives across joiner add/remove cycles, so callers
  * stash the binding here once and use the same handle for every
  * subsequent join. */
 private suspend fun ensureJoinerNBinding(): JoinerNVpnBinding {
 activeJoinerNBinding?.let { return it }
 val app = getApplication<android.app.Application>().applicationContext
 val binding = bindJoinerNVpnService(app)
 activeJoinerNBinding = binding
 return binding
 }

 /** Convert one parsed wg-quick + tunnel id into a JoinerConfig
  * the [JoinerNController] can swallow. */
 private fun buildJoinerNConfig(
 id: String,
 configText: String,
 parsed: JoinerVpnConfig,
 ): JoinerNController.JoinerConfig =
 JoinerNController.JoinerConfig(
 tunnelId = id,
 addresses = parsed.addresses,
 routes = parsed.routes,
 mtu = parsed.mtu,
 wgQuickUapi = WgQuickUapi.render(configText),
 dnsServers = parsed.dnsServers,
 )

 // ---------------------------- HostModeReconfigurer

 /**
 * hook called by [com.gutschke.wgrtc.data.ListenerHub]
 * after a host-mode tunnel has accepted a new peer (5).
 * If the host tunnel is currently the active VPN, do a quick
 * `setState(UP, newConfig)` so wg-go's peer list picks up the
 * new `[Peer]` block — by the time the client receives ENROLL_OK
 * a few hundred milliseconds later, the host's wg-go is already
 * accepting its first handshake. Median cycle latency on real
 * hardware is ~57 ms (per
 * ``).
 *
 * No-op when [tunnelId] isn't the active tunnel: the operator
 * will pick up the new peer the next time they tap Connect on
 * the host tunnel (the persisted [HostModeConfig.enrolledPeers]
 * is the source of truth).
 */
 override suspend fun reconfigureHostTunnel(
 tunnelId: String, newConfigText: String,
 ) {
 // The unified gate: skip the IpcSet when this tunnel
 // isn't actually a live host slot.  Joiner tunnels can't
 // host so they're trivially skipped by the
 // hostModeBackend membership check.
 val modeABackend = WgrtcApp.instance.hostModeBackend
 if (!modeABackend.activeTunnelIds.value.contains(tunnelId)) {
 Log.i("wgrtc-vm",
 "host-mode reconfig: tunnel $tunnelId not active; " +
 "deferring wg-go reload until next Connect")
 return
 }
 // In-place IpcSet, no DOWN cycle. Look up the canonical
 // tunnel by id so the Tunnel → UAPI conversion sees the
 // up-to-date enrolledPeers list.
 val tunnel = _tunnels.value.firstOrNull { it.id == tunnelId } ?: return
 try {
 withContext(Dispatchers.IO) { modeABackend.reconfigure(tunnel) }
 Log.i("wgrtc-vm",
 "host-mode reconfig: refreshed wg-go peer list for $tunnelId")
 } catch (t: Throwable) {
 Log.e("wgrtc-vm",
 "host-mode reconfig failed for $tunnelId", t)
 }
 }

 /** Start the ~1 Hz polling loop that reads RX/TX counters from the
 * backend, computes deltas, and pushes results onto [throughput].
 * Idempotent: cancels any previous job first.
 *
 * Source-of-truth selection happens per tick: the host-mode
 * runner's UAPI dump wins when a host tunnel is active,
 * otherwise we read from the active joiner.  Per-tunnel entries
 * are written into [_throughput] / [_peerStats] keyed by
 * `tunnel.id` so the UI can render N independent host
 * tunnels at once. */
 private fun startThroughputSampler() {
 throughputJob?.cancel()
 throughputJob = viewModelScope.launch(Dispatchers.IO) {
 val baselines = mutableMapOf<String, SampleBaseline>()
 // Seed via an immediate sample (rates start at 0).
 sampleOnce(baselines, seeding = true)
 while (isActive) {
 delay(1_000)
 sampleOnce(baselines, seeding = false)
 }
 }
 }

 /** One throughput tick — refreshes [_throughput] / [_peerStats]
 * for every currently-active tunnel (joiner + each running host
 * slot).  Updates [baselines] in place so the next tick can
 * compute correct per-second rates.  Drops entries for tunnels
 * that aren't active any more so a freshly-stopped slot doesn't
 * leak stale counters. */
 private fun sampleOnce(
 baselines: MutableMap<String, SampleBaseline>,
 seeding: Boolean,
 ) {
 val hostBackend = WgrtcApp.instance.hostModeBackend
 val hostIds = hostBackend.activeTunnelIds.value
 val joinerId = _activeJoinerTunnelId.value
 val joinerBinding = activeJoinerBinding
 val now = System.nanoTime()
 val tps = mutableMapOf<String, ThroughputStats>()
 val pps = mutableMapOf<String, Map<String, com.gutschke.wgrtc.data.PeerStats>>()
 for (id in hostIds) {
 val stats = try { hostBackend.snapshotStats(id) } catch (t: Throwable) {
 if (seeding) Log.w("wgrtc-vm", "initial host sample $id failed", t)
 else Log.w("wgrtc-vm", "host sample $id failed; retrying", t)
 null
 } ?: continue
 recordSample(id, stats, now, seeding, baselines, tps, pps)
 }
 if (joinerId != null && joinerBinding != null) {
 val stats = try { joinerBinding.service.snapshotStats() } catch (t: Throwable) {
 if (seeding) Log.w("wgrtc-vm", "initial joiner sample failed", t)
 else Log.w("wgrtc-vm", "joiner sample failed; retrying", t)
 null
 }
 if (stats != null) {
 recordSample(joinerId, stats, now, seeding, baselines, tps, pps)
 }
 }
 // Prune baselines for tunnels that are no longer active so
 // the next start-cycle reseeds cleanly.
 val activeIds = hostIds + listOfNotNull(joinerId)
 baselines.keys.retainAll(activeIds)
 _throughput.value = tps
 _peerStats.value = pps
 }

 private fun recordSample(
 id: String,
 stats: UapiStats,
 now: Long,
 seeding: Boolean,
 baselines: MutableMap<String, SampleBaseline>,
 tps: MutableMap<String, ThroughputStats>,
 pps: MutableMap<String, Map<String, com.gutschke.wgrtc.data.PeerStats>>,
 ) {
 val prev = baselines[id]
 val rx = stats.totalRxBytes
 val tx = stats.totalTxBytes
 val (rxRate, txRate) = if (seeding || prev == null) 0.0 to 0.0 else {
 val dtSec = (now - prev.atNanos).coerceAtLeast(1).toDouble() / 1e9
 val r = ((rx - prev.rxBytes).coerceAtLeast(0)) / dtSec
 val t = ((tx - prev.txBytes).coerceAtLeast(0)) / dtSec
 r to t
 }
 tps[id] = ThroughputStats(
 rxBytes = rx, txBytes = tx,
 rxBytesPerSec = rxRate, txBytesPerSec = txRate,
 lastHandshakeEpochMs = stats.mostRecentHandshakeEpochMs,
 )
 pps[id] = stats.peers
 baselines[id] = SampleBaseline(rx, tx, now)
 }

 private data class SampleBaseline(val rxBytes: Long, val txBytes: Long, val atNanos: Long)

 private fun stopThroughputSampler() {
 throughputJob?.cancel()
 throughputJob = null
 _throughput.value = emptyMap()
 _peerStats.value = emptyMap()
 }

 private companion object {
 /** how long [connect] is willing to wait for a fresh OFFER
 * to land in the hub's candidate cache after firing a wake.
 * Picked above the typical OFFER round-trip (~600 ms LAN, ~1 s
 * STUN cycle) but short enough that the user doesn't perceive
 * Connect as sluggish. */
 const val FRESH_OFFER_WAIT_MS = 1_500L

 /** cached candidates younger than this are used immediately
 * without waiting for a refresh — STUN IPs don't rotate that
 * fast and the listener catches changes anyway. Keeps the
 * common case (cache populated by an active listener) at zero
 * added latency. */
 const val FRESH_OFFER_THRESHOLD_MS = 30_000L
 }
}
