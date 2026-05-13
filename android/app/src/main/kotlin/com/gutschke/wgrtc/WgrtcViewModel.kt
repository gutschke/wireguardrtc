package com.gutschke.wgrtc

import android.app.Application
import android.util.Log
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.gutschke.wgrtc.data.HostModeFactory
import com.gutschke.wgrtc.data.HostModeReconfigurer
import com.gutschke.wgrtc.data.JoinerVpnBinding
import com.gutschke.wgrtc.data.JoinerVpnConfig
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
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
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

 /** The id of the tunnel currently UP, or null. */
 private val _activeTunnelId = MutableStateFlow<String?>(null)
 val activeTunnelId: StateFlow<String?> = _activeTunnelId.asStateFlow()

 /** Set by paths that intentionally drive an in-place reconfigure
 * on a tunnel that is already UP, so a transient DOWN→UP cycle
 * in the underlying runner doesn't briefly null
 * [_activeTunnelId] and leave the UI flickering "Idle". */
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

 /** State string ("DOWN", "UP", "TOGGLE", "FAILED", …) for the live tunnel. */
 private val _liveState = MutableStateFlow("DOWN")
 val liveState: StateFlow<String> = _liveState.asStateFlow()

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

 /** Sampled RX/TX counters + per-second rate for the live tunnel.
 * `null` while no tunnel is active (or while the first sample
 * hasn't been taken yet, which is sub-second). */
 private val _throughput = MutableStateFlow<ThroughputStats?>(null)
 val throughput: StateFlow<ThroughputStats?> = _throughput.asStateFlow()
 private var throughputJob: Job? = null

 /** Per-peer slice of the active tunnel's stats. Map key is the
 * peer's base64 pubkey (matches [EnrolledPeer.pubkeyB64]).
 * Empty when no tunnel is up; refreshed at the same ~1 Hz
 * cadence as [throughput]. Used by the host-mode peer list
 * to render "Last handshake N s ago" per row. */
 private val _peerStats =
 MutableStateFlow<Map<String, com.gutschke.wgrtc.data.PeerStats>>(emptyMap())
 val peerStats: StateFlow<Map<String, com.gutschke.wgrtc.data.PeerStats>> =
 _peerStats.asStateFlow()

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

 /** tracks the in-flight connect coroutine so [disconnect]
 * can cancel it. Without this, disconnect's setState(DOWN) and
 * the race's next setEndpoint/setState(UP) interleave and the
 * user observes "Disconnect didn't disconnect". Stored as
 * `coroutineContext[Job]` from inside connect's body. */
 @Volatile private var connectJob: Job? = null

 /** roam handler. Constructed in the joiner-mode connect
 * success path; stopped on disconnect. Listens (via
 * [networkChangeMonitor]) for Android network changes and
 * drives an in-place re-race through the *existing*
 * TunnelEndpointController whenever the live handshake goes
 * stale. No JoinerVpnService rebind — just `setEndpoint` calls
 * into the running wireguard-go via UAPI. */
 @Volatile private var activeRoamController:
 com.gutschke.wgrtc.signalling.RoamController? = null

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
 val id = _activeTunnelId.value ?: return@NetworkChangeMonitor
 Log.i("wgrtc-vm", "network change → force-wake tunnel $id")
 hub.wake(id, force = true)
 // also notify the roam handler so it can
 // re-race candidates if the network change made the
 // current live endpoint unreachable.
 activeRoamController?.onNetworkChanged()
 }
 }

 // (legacy GoBackend tunnel-state listener removed in the
 // wgbridge_native path manages its lifecycle through
 // activeJoinerBinding + hostModeBackend.activeTunnelId.)

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
 // HostModeBackend.start). Mirrors the host-mode connect
 // branch at the top of `connect()`. Joiner-side recovery is
 // a separate problem — the bound JoinerVpnService is per-
 // Context, so a new Activity always starts unbound.
 WgrtcApp.instance.hostModeBackend.activeTunnelId?.let { liveId ->
  _activeTunnelId.value = liveId
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
 if (_activeTunnelId.value == evt.tunnelId) {
 reconfiguringTunnelId = evt.tunnelId
 try {
 // Live endpoint update: route through the
 // joiner service's in-place UAPI reconfigure.
 // Host () tunnels never have their
 // Endpoint = line rewritten by the listener,
 // so this is only load-bearing for
 // joiner-side roam.
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
 }
 }
 }
 }

 fun clearError() { _lastError.value = null }

 // ---------------------------------------------------------------- CRUD

 fun deleteTunnel(id: String) {
 viewModelScope.launch {
 if (_activeTunnelId.value == id) disconnect()
 hub.stop(id)
 val updated = _tunnels.value.filterNot { it.id == id }
 _tunnels.value = updated
 withContext(Dispatchers.IO) { hub.saveTunnels(updated) }
 }
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
 if (_activeTunnelId.value == updated.id) {
 disconnect()
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

 /** Common path for adding either flavour: append, persist, and
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
 // Register this coroutine as the active connect job; clear
 // on exit (success or failure) so the next disconnect doesn't
 // try to cancel a finished job.
 connectJob = currentCoroutineContext()[Job]
 // Mark the tunnel as "connecting" immediately so the UI can
 // show a per-row spinner. Cleared in the finally block at
 // the bottom of this function.
 _connectingTunnelId.value = id
 val t = _tunnels.value.firstOrNull { it.id == id }
 ?: error("no tunnel with id $id")
 // ─── Host () short-circuit ────────────────────────
 // Host-mode tunnels run on wgbridge_native's gvisor netstack.
 // There's no candidate race for a host (no daemon-driven
 // OFFERs to wait for) and no DOWN→UP cycle on revoke
 // (IpcSet handles in-place reconfigure).
 if (t.source == Tunnel.Source.HOST_MODE) {
 try {
 WgrtcApp.instance.hostModeBackend.start(t)
 _activeTunnelId.value = id
 _liveState.value = "UP"
 _lastError.value = null
 startThroughputSampler()
 Log.i("wgrtc-vm", "connect: host tunnel $id is up")
 } catch (e: Throwable) {
 Log.e("wgrtc-vm", "host start failed", e)
 _activeTunnelId.value = null
 _liveState.value = "DOWN"
 _lastError.value = "Host start failed: ${e.message}"
 throw e
 } finally {
 if (_connectingTunnelId.value == id) _connectingTunnelId.value = null
 if (connectJob == currentCoroutineContext()[Job]) connectJob = null
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
 val runner = ConnectionRunner(controller)
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
 )
 when (r) {
 is ConnectAttemptResult.Success -> {
 Log.i("wgrtc-vm",
 "connect: race succeeded on " +
 "${r.finalEndpoint.ip}:${r.finalEndpoint.port} " +
 "(egress=${r.egressInterface ?: "default"}, " +
 "wait=${r.handshakeWaitMs}ms)")
 _activeTunnelId.value = id
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
 _activeTunnelId.value = null
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
 _activeTunnelId.value = id
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
 _activeTunnelId.value = null
 // stop the network monitor on failure too — without
 // this, an earlier successful connect's monitor stays
 // registered firing wakes for an _activeTunnelId that's
 // now null. Idempotent.
 networkChangeMonitor.stop()
 activeRoamController?.stop()
 activeRoamController = null
 throw t
 } finally {
 // Only clear if WE are still the registered job (not a
 // later connect that overtook us).
 if (connectJob == currentCoroutineContext()[Job]) connectJob = null
 // Same guard for the connecting indicator: don't clear
 // a different tunnel's pending connect.
 if (_connectingTunnelId.value == id) _connectingTunnelId.value = null
 }
 }

 suspend fun disconnect() {
 // cancel any in-flight connect race so disconnect's
 // setState(DOWN) is the LAST backend mutation, not racing
 // the next setEndpoint of an unfinished candidate sweep.
 // cancelAndJoin waits for the cancellation to settle —
 // ConnectionRunner's delay() / setState calls are
 // cooperatively cancellable.
 connectJob?.let {
 try { it.cancelAndJoin() }
 catch (e: Throwable) { Log.w("wgrtc-vm", "connect cancel failed", e) }
 }
 connectJob = null
 stopThroughputSampler()
 networkChangeMonitor.stop()
 activeRoamController?.stop()
 activeRoamController = null
 // path takes precedence — if the active tunnel is
 // running on wgbridge, never call into GoBackend (whose
 // single tunnel slot is unrelated to the runner) so
 // we don't accidentally cycle a sibling.
 val modeABackend = WgrtcApp.instance.hostModeBackend
 if (modeABackend.activeTunnelId != null) {
 try { modeABackend.stop() }
 catch (t: Throwable) {
 Log.e("wgrtc-vm", "stop failed", t)
 }
 _activeTunnelId.value = null
 _liveState.value = "DOWN"
 return
 }
 // WGBRIDGE joiner path — same precedence reasoning.
 // The bound JoinerVpnService owns wireguard-go for the
 // joiner tunnel; calling setState on wireguard-android's
 // GoBackend is a no-op at best, a process-wide
 // dual-runtime hazard at worst.
 activeJoinerBinding?.let { binding ->
 try { binding.service.stop() }
 catch (t: Throwable) {
 Log.e("wgrtc-vm", "joiner stop failed", t)
 }
 binding.unbind()
 activeJoinerBinding = null
 }
 _activeTunnelId.value = null
 _liveState.value = "DOWN"
 }

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
 if (_activeTunnelId.value != tunnelId) {
 Log.i("wgrtc-vm",
 "host-mode reconfig: tunnel $tunnelId not active; " +
 "deferring wg-go reload until next Connect")
 return
 }
 // In-place IpcSet, no DOWN cycle. Look up the canonical
 // tunnel by id so the Tunnel → UAPI conversion sees the
 // up-to-date enrolledPeers list.
 val modeABackend = WgrtcApp.instance.hostModeBackend
 if (modeABackend.activeTunnelId != tunnelId) return
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
 * otherwise we read from the active joiner. Both feed the
 * same [ThroughputStats] / [_peerStats] flows so the
 * status line is source-agnostic. */
 private fun startThroughputSampler() {
 throughputJob?.cancel()
 _throughput.value = null
 throughputJob = viewModelScope.launch(Dispatchers.IO) {
 var prevRx = 0L
 var prevTx = 0L
 var prevAt = System.nanoTime()
 // Seed via an immediate sample (rates start at 0).
 sampleOnce(prevRx, prevTx, prevAt, seeding = true)?.let {
 prevRx = it.rxBytes; prevTx = it.txBytes; prevAt = it.atNanos
 }
 while (isActive) {
 delay(1_000)
 sampleOnce(prevRx, prevTx, prevAt, seeding = false)?.let {
 prevRx = it.rxBytes; prevTx = it.txBytes; prevAt = it.atNanos
 }
 }
 }
 }

 /** One throughput sample. Picks the live source (host
 * backend or the active joiner runner), updates [_throughput]
 * / [_peerStats], and returns the new baseline values (or null
 * when the source refused to give us a reading this tick). */
 private fun sampleOnce(
 prevRx: Long, prevTx: Long, prevAt: Long, seeding: Boolean,
 ): SampleBaseline? {
 val modeABackend = WgrtcApp.instance.hostModeBackend
 val stats: UapiStats = when {
 modeABackend.activeTunnelId != null ->
 modeABackend.snapshotStats() ?: return null
 activeJoinerBinding != null ->
 activeJoinerBinding?.service?.snapshotStats() ?: return null
 else -> return null
 }
 return try {
 val rx = stats.totalRxBytes
 val tx = stats.totalTxBytes
 val now = System.nanoTime()
 val dtSec = (now - prevAt).coerceAtLeast(1).toDouble() / 1e9
 _throughput.value = ThroughputStats(
 rxBytes = rx, txBytes = tx,
 rxBytesPerSec = if (seeding) 0.0 else ((rx - prevRx).coerceAtLeast(0)) / dtSec,
 txBytesPerSec = if (seeding) 0.0 else ((tx - prevTx).coerceAtLeast(0)) / dtSec,
 lastHandshakeEpochMs = stats.mostRecentHandshakeEpochMs,
 )
 _peerStats.value = stats.peers
 SampleBaseline(rx, tx, now)
 } catch (t: Throwable) {
 if (seeding) Log.w("wgrtc-vm", "initial sampleOnce failed", t)
 else Log.w("wgrtc-vm", "sampleOnce failed; retrying next tick", t)
 null
 }
 }

 private data class SampleBaseline(val rxBytes: Long, val txBytes: Long, val atNanos: Long)

 private fun stopThroughputSampler() {
 throughputJob?.cancel()
 throughputJob = null
 _throughput.value = null
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
