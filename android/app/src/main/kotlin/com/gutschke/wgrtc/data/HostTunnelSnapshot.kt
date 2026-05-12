package com.gutschke.wgrtc.data

/**
 * Read-only view of a HOST_MODE tunnel snapshotted at the moment a
 * wormhole-code session is initiated. Contains everything the
 * [WormholeHostController] needs to assemble a [com.gutschke.wgrtc.signalling.HostEnrolInfo]
 * payload — without the controller having to depend on
 * [TunnelStore], [HostSubnetAllocator], or anything else from the
 * persistence layer. That keeps the controller pure-protocol and
 * unit-testable on plain JVM.
 *
 * The caller (typically the UI / ViewModel) builds this snapshot
 * by reading the tunnel from the store, picking the next free IP
 * via [HostSubnetAllocator.nextFreeIp], and wiring in the broker
 * settings (per-tunnel if the host has overridden, default
 * otherwise).
 *
 * **Pre-allocated IP**: [assignedAddress] is the IP the host has
 * earmarked for the joining client. It's not yet committed to the
 * tunnel — that happens when [WormholeHostController.successResult]
 * fires and the UI calls into the existing
 * [applyEnrollmentToTunnel] path. If the wormhole fails or is
 * cancelled, the IP slot is simply not used; nothing to roll back.
 */
data class HostTunnelSnapshot(
    /** [Tunnel.id] — used by the UI to know which tunnel to update
     * on success. Not embedded in any wire payload. */
    val tunnelId: String,
    /** Standard-base64 32-byte WG private key (the host's). */
    val privKeyB64: String,
    /** Standard-base64 32-byte WG public key (derivable from
     * [privKeyB64], cached here so the controller doesn't recompute). */
    val pubKeyB64: String,
    /** "ip:port" — the address joiners use as their `[Peer] Endpoint`.
     * Typically the host's roamed STUN address or LAN address; the
     * caller picks based on the deployment scenario. */
    val wgEndpoint: String,
    /** `[Peer] AllowedIPs` for the joiner. Often the host's subnet
     * CIDR (e.g. `10.99.0.0/24`) so the joiner can reach the host
     * + any other peers; could be `0.0.0.0/0` for full-tunnel. */
    val allowedIps: String,
    /** Pre-allocated address for the joining client (e.g.
     * `10.99.0.2/32`). See class kdoc. */
    val assignedAddress: String,
    /** Per-tunnel broker the joiner should subscribe to after
     * enrolment for OFFER traffic. Default broker (from
     * [SettingsStore]) is fine; per-tunnel override goes here. */
    val brokerWss: String,
    val brokerKey: String,
    /** URL-safe base64 of the host's salt (for routing-id derivation). */
    val saltB64: String,
    /** Optional human-readable host label — surfaces in the
     * joiner's tunnel name. */
    val hostName: String? = null,
    val dns: String? = null,
    val mtu: Int? = null,
    val keepalive: Int? = 25,
)

/**
 * Result of a successful host-side wormhole exchange — the data
 * needed to persist the new peer in the host's tunnel via the
 * existing [applyEnrollmentToTunnel] path.
 */
data class HostWormholeResult(
    /** The host tunnel this enrolment belongs to. */
    val tunnelId: String,
    /** Joiner's WG public key. Goes into the new `[Peer] PublicKey`. */
    val joinerPubkeyB64: String,
    /** IP the host pre-allocated and is now committing to this
     * joiner. Same value as the snapshot's [HostTunnelSnapshot.assignedAddress]
     * but stripped of the `/32` suffix for [EnrolledPeer.assignedIp]. */
    val joinerIp: String,
    /** Free-form name from the joiner (device label). Defaults
     * to a stable derived value if absent. */
    val joinerNameHint: String,
    /** Manual-flow only: the wg-quick text the host minted for this
     * joiner. Persisted on the resulting [EnrolledPeer] so the
     * host UI's "Show invitation" action survives a restart.
     * Null for QR / wormhole enrolments where the host never sees
     * the joiner's privkey. */
    val manualInvitationText: String? = null,
)
