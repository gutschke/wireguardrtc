package com.gutschke.wgrtc.data

/**
 * Authoritative per-tunnel state.  See `docs/ux-design-v2.md` §1
 * for the model.
 *
 * Nine logical states (some carry a structured reason payload):
 *
 *  * [Disabled]            — saved, not asked-for.  Freshly-imported tunnels
 *                            (paste, QR, wormhole completion) land here;
 *                            import does NOT auto-Connect.
 *  * [Pairing]             — wormhole-pairing in flight (SAS, key derivation,
 *                            enrolment).  Pre-tunnel: no UDP socket yet.
 *  * [Arming]              — user tapped Connect; gathering preconditions
 *                            (consent grant, port bind, key load).
 *  * [Connecting]          — preconditions satisfied; handshake in flight.
 *  * [Connected]           — handshake < 180 s ago AND bridge alive AND
 *                            consent valid.
 *  * [Idle]                — Connected-by-config but no recent handshake
 *                            (joiner with no traffic and no keepalive;
 *                            not a fault).
 *  * [Degraded]            — handshake stale but socket alive; auto-recovery
 *                            in progress.
 *  * [PausedSystem]        — Android revoked the VpnService, OR another VPN
 *                            took over, OR Doze killed the foreground
 *                            service.  Distinct from user pause.
 *  * [PausedUser]          — user flipped the row switch off; sticky across
 *                            reboots.
 *  * [Failed]              — failure with [Failed.cause] enumerating the
 *                            reason.  [Failed.recoverable] discriminates
 *                            "next network event re-arms" from "requires
 *                            user action".
 *
 * **Invariant**: state is derived from observable signals (handshake time,
 * consent freshness, bridge liveness), never stored.  See §1.3.
 *
 * **Serialisation**: this class is NOT persisted.  The persistent equivalent
 * lives in [Tunnel.intent] ([TunnelIntent]); the runtime state is rebuilt
 * from UAPI dumps + service state on process restart.
 */
sealed class TunnelState {

    /** Saved, never-asked-for, freshly-imported.  Maps to
     *  [TunnelIntent.NoIntentYet]. */
    object Disabled : TunnelState() {
        override fun toString() = "Disabled"
    }

    /** Wormhole-pairing in flight — SAS exchange, key derivation,
     *  enrolment-payload swap.  Tunnel has no UDP socket yet, so this
     *  state precedes [Arming]. */
    object Pairing : TunnelState() {
        override fun toString() = "Pairing"
    }

    /** User tapped Connect; preconditions being gathered (VPN
     *  consent, listen-port bind, key load).  Transitions to
     *  [Connecting] on `nativeBridge.deviceReady` (or equivalent
     *  per-mode signal) or to [Failed] on precondition violation. */
    object Arming : TunnelState() {
        override fun toString() = "Arming"
    }

    /** Preconditions satisfied; WireGuard handshake in flight.
     *  Transitions to [Connected] on first non-zero handshake or
     *  [Failed] on timeout / endpoint-unreachable. */
    object Connecting : TunnelState() {
        override fun toString() = "Connecting"
    }

    /** Handshake completed recently, bridge alive, consent valid.
     *  Derived: `lastHandshakeTime > now - HANDSHAKE_STALE_SEC AND
     *  bridgeAlive AND !consentRevoked`. */
    object Connected : TunnelState() {
        override fun toString() = "Connected"
    }

    /** Connected-by-config but no recent handshake (joiner with no
     *  traffic AND no PersistentKeepalive).  NOT a fault — the wire
     *  spec allows this; the next tx packet re-arms.  See §1.2 for
     *  Idle→Connecting triggers. */
    object Idle : TunnelState() {
        override fun toString() = "Idle"
    }

    /** Handshake stale but socket alive — typically a network
     *  transition (Wi-Fi → cellular roam, captive portal, etc.).
     *  Auto-recovery in progress via the offer-listener endpoint
     *  refresh + the next `onAvailable` callback. */
    object Degraded : TunnelState() {
        override fun toString() = "Degraded"
    }

    /** Android-revoked: VpnService consent was withdrawn (Settings
     *  toggle off / force-stop / another VPN took over / Doze
     *  killed the FGS).  [reason] discriminates which signal caught
     *  it — useful for UI copy and diagnostic logging. */
    data class PausedSystem(val reason: PauseReason) : TunnelState() {
        override fun toString() = "PausedSystem($reason)"
    }

    /** User flipped the row switch off after the tunnel was on.
     *  Sticky across reboots; survives upgrades.  Distinct from
     *  [Disabled] (which means "never asked-for" — different
     *  semantics for the resume prompt). */
    object PausedUser : TunnelState() {
        override fun toString() = "PausedUser"
    }

    /** Failure with a structured cause.  [recoverable] = true means
     *  the next network event auto-re-arms; false means the user
     *  must intervene (consent grant, key swap, config edit).
     *  See `docs/ux-design-v2.md` §4.1 for the cause → human-message
     *  mapping. */
    data class Failed(
        val cause: FailureCause,
        val recoverable: Boolean,
    ) : TunnelState() {
        override fun toString() = "Failed(${cause}, recoverable=$recoverable)"
    }

    companion object {
        /** WireGuard `RejectAfterTime` — the wire-spec threshold past
         *  which a session is considered dead.  Connected → Idle
         *  fires when `now - lastHandshakeTime > HANDSHAKE_STALE_SEC`. */
        const val HANDSHAKE_STALE_SEC: Long = 180
    }
}

/** Why a [TunnelState.PausedSystem] was entered.  Diagnostic; the
 *  UI shows the same "system paused" copy regardless. */
enum class PauseReason {
    /** Detected via `builder.establish()` returning null on the next
     *  Connect attempt.  Dominant signal for "user toggled VPN
     *  permission off in Settings" / "force-stopped". */
    EstablishNull,

    /** `VpnService.onRevoke()` fired — typically another VPN app
     *  took over.  Cheap, narrow scope. */
    AnotherVpnTookOver,

    /** `MainActivity.onResume` re-ran `VpnService.prepare()` and got
     *  a non-null Intent back, meaning consent has been withdrawn
     *  between connects.  Catches the user-never-tried-to-connect
     *  case where [EstablishNull] wouldn't fire. */
    ForegroundResync,

    /** `OfferListenerService` periodic re-`prepare()` (WorkManager
     *  @ 30 min, gated on at least one joiner with
     *  `intent=WantsOn`).  Catches the user-never-foregrounds-the-app
     *  case for phantom-active windows of hours/days. */
    BackgroundResync,

    /** Doze killed the foreground service.  Distinct because the
     *  app should ask the user to allow the FGS exception, not the
     *  VPN consent. */
    FgsKilledByDoze,
}

/** Structured failure cause.  See `docs/ux-design-v2.md` §4.1 for
 *  the message + remediation mapping. */
sealed class FailureCause {
    /** `VpnService.prepare()` returned a consent Intent, the user
     *  was prompted, and tapped Cancel.  Recoverable: tap Reconnect
     *  triggers another prepare. */
    object ConsentDenied : FailureCause() { override fun toString() = "ConsentDenied" }

    /** Android 14+: `prepare()` returned a consent Intent, the
     *  Activity launched it, but `onActivityResult` came back
     *  without a result (silent denial — typically the App-Info
     *  permission toggle was used).  Permanent: needs the user to
     *  open App-Info themselves. */
    object ConsentSilentlyDenied : FailureCause() { override fun toString() = "ConsentSilentlyDenied" }

    /** UDP bind failed with EADDRINUSE.  Holder uid not surfaced
     *  (gated at API 29+).  Recoverable: user re-runs with a
     *  different ListenPort. */
    data class PortInUse(val port: Int) : FailureCause()

    /** No signaling server configured.  User deleted the default
     *  broker; offer-listener has nothing to connect to. */
    object BrokerMissing : FailureCause() { override fun toString() = "BrokerMissing" }

    /** Signaling server unreachable.  Network issue or stale URL. */
    data class BrokerUnreachable(val url: String) : FailureCause()

    /** Remote peer rejected our public key.  Either the remote
     *  removed this device or the on-disk key material is corrupt.
     *  Permanent: needs user intervention (Edit / re-enrol). */
    object PeerKeyRejected : FailureCause() { override fun toString() = "PeerKeyRejected" }

    /** WireGuard handshake never completed.  Endpoint may be
     *  unreachable, NAT may have closed the path, or the remote is
     *  down.  Recoverable: next network event triggers a re-arm. */
    data class HandshakeTimeout(val endpoint: String) : FailureCause()

    /** User confirmed (via §6.2 ChromeOS dialog) that another local
     *  WG client routes through this tunnel.  Permanent: needs the
     *  user to fix the other client. */
    object RoutingLoopUserConfirmed : FailureCause() { override fun toString() = "RoutingLoopUserConfirmed" }

    /** Per-host `relayPolicy=Never` blocked the cascade.  Not a
     *  real failure; surfaced this way only because cascade is the
     *  "expected" path for some user flows.  Recoverable: flip the
     *  policy. */
    object CascadePolicyBlocked : FailureCause() { override fun toString() = "CascadePolicyBlocked" }

    /** SAS-mismatch or broker timeout during wormhole pairing.
     *  Recoverable: re-enter the wormhole code. */
    object PairingSasMismatch : FailureCause() { override fun toString() = "PairingSasMismatch" }

    /** User cancelled the pairing flow OR the wormhole code
     *  expired.  Permanent: needs a fresh code from the other
     *  side. */
    object PairingCancelled : FailureCause() { override fun toString() = "PairingCancelled" }
}

/** Persistent user-intent for a tunnel.  Survives reboots; written
 *  alongside the [Tunnel] config.  Maps deterministically to the
 *  starting state when the registry rebuilds from disk:
 *
 *  | Intent          | Starting state          |
 *  |-----------------|-------------------------|
 *  | NoIntentYet     | Disabled                |
 *  | WantsOn         | Arming (re-derive live) |
 *  | ExplicitlyOff   | PausedUser              |
 */
enum class TunnelIntent {
    /** Never asked-for.  Freshly-imported / pre-migration tunnels
     *  land here.  Maps to [TunnelState.Disabled]. */
    NoIntentYet,

    /** User flipped the switch on.  The live state derives from
     *  signals — [TunnelState.Arming], [TunnelState.Connecting],
     *  [TunnelState.Connected], etc. */
    WantsOn,

    /** User flipped the switch off after having it on (or after a
     *  [TunnelState.PausedSystem] transition).  Maps to
     *  [TunnelState.PausedUser]. */
    ExplicitlyOff,
}
