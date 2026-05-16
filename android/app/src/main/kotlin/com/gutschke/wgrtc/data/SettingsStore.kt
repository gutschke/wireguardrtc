package com.gutschke.wgrtc.data

import android.content.Context
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Persistent app-level settings. Currently just the *default*
 * broker coordinates used for the wormhole-code initial rendezvous;
 * per-tunnel broker info (carried in [Tunnel.brokerWss] /
 * [Tunnel.brokerKey]) takes precedence wherever a specific tunnel
 * is in scope.
 *
 * Deployment scenarios:
 *
 * 1. **Default-broker only** — no setup; both sides use
 * [WormholeDefaults.BROKER_WSS] for first contact. Per-tunnel
 * broker (from 's enrollment payload) takes over afterwards
 * so the public broker never sees post-enrollment OFFER frames.
 * 2. **Private broker only** — user overrides the default below.
 * Both sides MUST configure the same private broker for the
 * initial rendezvous; that's the cost of opting out.
 * 3. **Mixed (common)** — default broker for first contact, then
 * per-tunnel broker advertised via the SAS payload.
 * 4. **Auto-detected** — future work (mDNS-advertised broker on a
 * shared LAN, fallback to default). Not implemented.
 *
 * Backing-store split: [Backing] is a tiny key-value interface so
 * pure-JVM tests don't need SharedPreferences (or Robolectric).
 * Production calls [create] which wraps Android SharedPreferences;
 * tests use [forTestInMemory].
 */
class SettingsStore internal constructor(private val backing: Backing) {

    interface Backing {
        fun getString(key: String): String?
        fun putString(key: String, value: String)
        fun remove(key: String)
    }

    private val _wss = MutableStateFlow(
        backing.getString(K_BROKER_WSS) ?: WormholeDefaults.BROKER_WSS)
    private val _key = MutableStateFlow(
        backing.getString(K_BROKER_KEY) ?: WormholeDefaults.BROKER_KEY)
    private val _egress = MutableStateFlow(
        parseEgressPolicy(backing.getString(K_EGRESS_POLICY)))
    private val _hideListenerNotification = MutableStateFlow(
        backing.getString(K_HIDE_LISTENER_NOTIFICATION) == "true")
    private val _joinerNEnabled = MutableStateFlow(
        // Default ON since v0.2.10: fresh installs and existing
        // installs that never touched the toggle both get the
        // shared-stack path. Users who explicitly set the toggle
        // off (the persisted value is the literal string "false")
        // keep their preference across upgrades.
        backing.getString(K_JOINER_N_ENABLED) != "false")

    val defaultBrokerWssFlow: StateFlow<String> = _wss.asStateFlow()
    val defaultBrokerKeyFlow: StateFlow<String> = _key.asStateFlow()

    /** Current egress policy for userspace-NAT outbound sockets.
     * See [EgressPolicy] for the semantics; default is
     * [EgressPolicy.OsDefault]. */
    val egressPolicyFlow: StateFlow<EgressPolicy> = _egress.asStateFlow()

    /** When true, the OfferListenerService's foreground-service
     * notification posts via a min-importance channel so it stays
     * out of the user's notification shade. The service still runs
     * (required to keep the long-lived signaling WSS alive across
     * app backgrounding) — only the visible badge is hidden. */
    val hideListenerNotificationFlow: StateFlow<Boolean> =
        _hideListenerNotification.asStateFlow()

    /** When true (default since v0.2.10), joiner-mode tunnels share
     * one VpnService TUN through a userspace gvisor netstack so the
     * device can keep more than one joiner up simultaneously (see
     * `docs/cascade-n-design.md`). When off, the legacy single-
     * joiner path takes over — at most one joiner active at a time.
     * Users who hit a regression specific to the shared stack can
     * toggle off and the previous behaviour is preserved. */
    val joinerNEnabledFlow: StateFlow<Boolean> = _joinerNEnabled.asStateFlow()

    var defaultBrokerWss: String
        get() = _wss.value
        set(value) {
            backing.putString(K_BROKER_WSS, value)
            _wss.value = value
        }

    var defaultBrokerKey: String
        get() = _key.value
        set(value) {
            backing.putString(K_BROKER_KEY, value)
            _key.value = value
        }

    var egressPolicy: EgressPolicy
        get() = _egress.value
        set(value) {
            backing.putString(K_EGRESS_POLICY, value.serialize())
            _egress.value = value
        }

    var hideListenerNotification: Boolean
        get() = _hideListenerNotification.value
        set(value) {
            backing.putString(K_HIDE_LISTENER_NOTIFICATION, value.toString())
            _hideListenerNotification.value = value
        }

    var joinerNEnabled: Boolean
        get() = _joinerNEnabled.value
        set(value) {
            backing.putString(K_JOINER_N_ENABLED, value.toString())
            _joinerNEnabled.value = value
        }

    /**
     * Whether the first-launch onboarding has been completed.
     * Read once on Application startup to decide whether the user
     * lands on the tunnel list or the onboarding flow.
     */
    var onboardingSeen: Boolean
        get() = backing.getString(K_ONBOARDING_SEEN) == "true"
        set(value) {
            backing.putString(K_ONBOARDING_SEEN, value.toString())
        }

    /** Snapshot getter for one-shot reads. */
    fun snapshot(): Snapshot = Snapshot(defaultBrokerWss, defaultBrokerKey)

    /** Restore the compiled-in defaults. */
    fun resetToDefaults() {
        backing.remove(K_BROKER_WSS)
        backing.remove(K_BROKER_KEY)
        backing.remove(K_EGRESS_POLICY)
        backing.remove(K_HIDE_LISTENER_NOTIFICATION)
        backing.remove(K_JOINER_N_ENABLED)
        // K_HOSTING_MODE / K_JOINER_BACKEND keys removed in
        // when wireguard-android went away; we also drop any
        // legacy persisted values so they don't linger in prefs.
        backing.remove(K_LEGACY_HOSTING_MODE)
        backing.remove(K_LEGACY_JOINER_BACKEND)
        _wss.value = WormholeDefaults.BROKER_WSS
        _key.value = WormholeDefaults.BROKER_KEY
        _egress.value = EgressPolicy.OsDefault
        _hideListenerNotification.value = false
        _joinerNEnabled.value = true
    }

    data class Snapshot(val brokerWss: String, val brokerKey: String)

    companion object {
        private const val PREFS_NAME = "wgrtc_settings"
        private const val K_BROKER_WSS = "broker_wss"
        private const val K_BROKER_KEY = "broker_key"
        private const val K_EGRESS_POLICY = "egress_policy"
        private const val K_ONBOARDING_SEEN = "onboarding_seen"
        private const val K_HIDE_LISTENER_NOTIFICATION = "hide_listener_notification"
        private const val K_JOINER_N_ENABLED = "joiner_n_enabled"
        // Legacy keys — read only during resetToDefaults() to
        // scrub leftover prefs from pre- installs. Never
        // written.
        private const val K_LEGACY_HOSTING_MODE = "hosting_mode"
        private const val K_LEGACY_JOINER_BACKEND = "joiner_backend"

        fun create(context: Context): SettingsStore {
            val prefs = context.applicationContext
                .getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            return SettingsStore(object : Backing {
                override fun getString(key: String): String? = prefs.getString(key, null)
                override fun putString(key: String, value: String) {
                    prefs.edit().putString(key, value).apply()
                }
                override fun remove(key: String) {
                    prefs.edit().remove(key).apply()
                }
            })
        }

        /** Test-friendly in-memory backing. Pre-populate via the
         * optional [seed] map. */
        fun forTestInMemory(seed: Map<String, String> = emptyMap()): SettingsStore {
            val map = HashMap(seed)
            return SettingsStore(object : Backing {
                override fun getString(key: String): String? = map[key]
                override fun putString(key: String, value: String) { map[key] = value }
                override fun remove(key: String) { map.remove(key) }
            })
        }
    }
}
