package com.gutschke.wgrtc.data

/**
 * Read-only view of a HOST_MODE tunnel snapshotted at the moment a
 * wormhole-code session is initiated. Contains everything the
 * [WormholeHostController] needs to assemble a [com.gutschke.wgrtc.signalling.HostEnrollInfo]
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
    /** Pre-allocated address(es) for the joining client.
     *
     * V6.3 — content may be a single CIDR (`10.99.0.2/32`, legacy
     * v4-only flow) OR a comma-separated dual-stack pair
     * (`10.99.0.2/32,fd00:dead:beef::2/128`).  Canonical (no
     * whitespace around commas, RFC 5952 compressed v6) — see
     * [WgAllowedIps] for the ChromeOS compat rationale.  Consumers
     * that need to extract the bare v4 or v6 use [splitAssignedAddress].
     *
     * Goes verbatim onto the joiner's `[Interface] Address = …`
     * line; [JoinerVpnConfig.parse] handles comma-separated. */
    val assignedAddress: String,
    /** Per-tunnel broker the joiner should subscribe to after
     * enrollment for OFFER traffic. Default broker (from
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
    /** The host tunnel this enrollment belongs to. */
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
     * Null for QR / wormhole enrollments where the host never sees
     * the joiner's privkey. */
    val manualInvitationText: String? = null,
    /** V6.3 — v6 sibling of [joinerIp], stripped of `/128`.
     * Null on tunnels without a `subnetV6` (legacy v4-only) and
     * on the daemon flow when the daemon's HostState had no v6
     * subnet at allocation time. */
    val joinerIpV6: String? = null,
)

/**
 * V6.3 — split a comma-separated `Address` / `assignedAddress`
 * value into bare v4 + v6 components (each without their `/N`
 * suffix).  Tolerates whitespace around commas (as
 * [WgAllowedIps.canonicalize] strips it).  Returns `(null, null)`
 * for an empty / unparseable input; either field may be null
 * individually.  Used by the host-side wormhole + manual-config
 * paths to derive [HostWormholeResult.joinerIp] /
 * [HostWormholeResult.joinerIpV6] from
 * [HostTunnelSnapshot.assignedAddress].
 */
internal fun splitAssignedAddress(value: String): Pair<String?, String?> {
    var v4: String? = null
    var v6: String? = null
    for (part in value.split(',')) {
        val s = part.trim()
        if (s.isEmpty()) continue
        val bare = s.substringBefore('/').trim()
        if (bare.isEmpty()) continue
        // v6 if it has a colon; v4 if dotted-quad.  Brackets
        // (`[fd00::1]/128` form) are stripped defensively.
        val stripped = if (bare.startsWith('[') && bare.endsWith(']'))
            bare.substring(1, bare.length - 1) else bare
        when {
            ':' in stripped -> if (v6 == null) v6 = stripped
            '.' in stripped -> if (v4 == null) v4 = stripped
        }
    }
    return v4 to v6
}
