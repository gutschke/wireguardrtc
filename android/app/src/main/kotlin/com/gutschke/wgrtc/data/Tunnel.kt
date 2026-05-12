package com.gutschke.wgrtc.data

import kotlinx.serialization.Serializable
import java.util.UUID

/**
 * A persisted tunnel record.
 *
 * For client-mode tunnels (LEGACY / ENROLL / MANUAL) the source of
 * truth is [configText] — a fully-resolved wg-quick
 * `[Interface]…[Peer]…` block. For ENROLL-source tunnels we
 * additionally retain the broker coordinates ([brokerWss],
 * [brokerKey], [saltB64]) so the long-lived `OfferListener` can
 * reconnect after process death and keep the tunnel's
 * `Endpoint = ` line in sync with the daemon's STUN-discovered IP as
 * it roams.
 *
 * For host-mode tunnels [hostMode] is non-null and carries
 * the host's subnet plus the canonical list of enrolled peers (each
 * with its assigned /32, the name hint from the token mint, and the
 * timestamp of enrolment). In that case [configText] is just the
 * `[Interface]` block — the per-peer `[Peer]` blocks are *rendered*
 * from [HostModeConfig.enrolledPeers] at the moment we hand the
 * config to wg-go (see [renderWgConfig]). This split keeps the
 * structured per-peer metadata (assigned IP, name) addressable
 * without parsing wg-quick.
 *
 * None of these fields are secret — the URI's `salt` is a public
 * routing constant; the broker URL is admin-published. Old
 * tunnels.json files that lack any of the optional fields
 * deserialise to the documented defaults.
 */
@Serializable
data class Tunnel(
    val id: String = UUID.randomUUID().toString(),
    val name: String,
    val configText: String,
    /** Origin tag, useful for display only. No code branches on this. */
    val source: Source = Source.LEGACY,
    val brokerWss: String? = null,
    val brokerKey: String? = null,
    /** URL-safe base64, no padding — same encoding the URI uses. */
    val saltB64: String? = null,
    /** host-mode state. Null for client-mode tunnels. */
    val hostMode: HostModeConfig? = null,
) {
    enum class Source { LEGACY, ENROLL, MANUAL, HOST_MODE }
}

/**
 * host-mode state: subnet + canonical list of enrolled
 * peers. See [Tunnel] kdoc for the split-of-concerns vs. wg-quick
 * `configText`.
 */
@Serializable
data class HostModeConfig(
    /** CIDR like `10.99.0.0/24` — pool the [HostSubnetAllocator]
     * draws from. */
    val subnet: String,
    /** Each enrolled peer keeps its assigned IP stable across
     * re-enrollments (we look it up by pubkey). */
    val enrolledPeers: List<EnrolledPeer> = emptyList(),
    /**
     * Routing claim the host advertises to joining clients, used as
     * the `[Peer] AllowedIPs` line in the joiner's wg-quick. Null
     * (the default) falls back to [subnet] — joiners only route
     * traffic destined for the WG subnet through the tunnel; their
     * regular network keeps providing internet. Set to `0.0.0.0/0`
     * (or `0.0.0.0/0, ::/0`) to advertise full-tunnel; set to
     * something specific (e.g. `10.0.0.0/8, 192.168.0.0/16`) for
     * routing only enterprise / home-LAN traffic through the host.
     *
     * Backward compat: missing on tunnels persisted before this
     * field existed; deserialisation gives the null default and the
     * subnet fallback applies.
     *
     * **Canonical format (no whitespace).** All write-paths into
     * this field (HostModeSetupScreen, edit form, programmatic
     * tests) canonicalize via [WgAllowedIps.canonicalize] before
     * persisting, so downstream wg-quick / SAS-payload renderers
     * never have to worry about spaces creeping in. See
     * [WgAllowedIps] kdoc for the ChromeOS compat constraint.
     */
    val advertisedAllowedIps: String? = null,
)

/** One peer that's been admitted by a host-mode tunnel. */
@Serializable
data class EnrolledPeer(
    /** Standard-base64 32-byte WG public key. */
    val pubkeyB64: String,
    /** Dotted-quad IPv4 the host allocated; written into the peer's
     * `[Peer] AllowedIPs` as `<ip>/32`. */
    val assignedIp: String,
    /** Free-form label the user supplied at token-mint time;
     * surfaces in the host UI's "active peers" list. */
    val nameHint: String,
    /** Epoch ms; ordering preserves enrolment order. */
    val enrolledAtMs: Long,
    /**
     * Optional snapshot of the wg-quick text the host minted for
     * this peer via the **manual** invitation flow. Lets the host
     * UI's "Show invitation" action survive an app restart so the
     * user can re-display the QR / text / per-field view to a
     * guest who hasn't imported it yet.
     *
     * **Security note:** the text contains the joiner's freshly
     * generated WG private key. Storing it on the host's disk is
     * a security trade-off vs. the in-memory cache:
     *
     * - Pro: durable across crash + restart (the user reported
     * losing it after the SIGSEGV-induced auto-restart).
     * - Con: a host's tunnels.json now carries privkeys for
     * every joiner that was invited via Manual, until the
     * peer is revoked. Mitigations: tunnels.json lives in
     * [Context.filesDir] which is per-app-uid private; the
     * field is dropped immediately when the peer is revoked.
     *
     * Wormhole / QR-token enrolments DON'T store this — the
     * joiner generates its own keypair locally, the host only
     * ever sees the joiner's pubkey. Only the Manual flow
     * (where the host mints both halves) populates this field.
     */
    val manualInvitationText: String? = null,
)

/**
 * Render the wg-quick text the host's wg-go should consume. For
 * client tunnels this is just [configText]; for host-mode tunnels
 * it's [configText] (the `[Interface]` block) followed by one
 * `[Peer]` block per [EnrolledPeer].
 *
 * **Always use this (or [kernelConfigStream]) for any wg-config
 * bytes destined for wireguard-go via UAPI.** Reading
 * [Tunnel.configText] directly works for client tunnels but
 * silently omits the [Peer] blocks of HOST_MODE tunnels —
 * happened because the connect path missed this distinction and
 * brought wg-go up with an empty peer table, dropping every
 * joiner's handshake.
 */
fun renderWgConfig(t: Tunnel): String {
    val hm = t.hostMode ?: return t.configText
    if (hm.enrolledPeers.isEmpty()) return t.configText
    val sb = StringBuilder(t.configText)
    if (!t.configText.endsWith("\n")) sb.append('\n')
    for (peer in hm.enrolledPeers) {
        sb.append('\n')
        sb.append("[Peer]\n")
        sb.append("PublicKey = ").append(peer.pubkeyB64).append('\n')
        sb.append("AllowedIPs = ").append(peer.assignedIp).append("/32\n")
    }
    return sb.toString().trimEnd('\n')
}

/**
 * Wg-quick bytes the wireguard-go runtime should consume when
 * bringing this tunnel up. Equivalent to
 * `renderWgConfig(this).byteInputStream()` but named so call sites
 * self-document at code-review time. See the regression in
 * [com.gutschke.wgrtc.data.RenderWgConfigContractTest].
 */
fun Tunnel.kernelConfigStream(): java.io.InputStream =
    renderWgConfig(this).byteInputStream()

/** Set of currently-allocated IPs in [t]. Empty for client tunnels. */
fun allocatedIps(t: Tunnel): Set<String> =
    t.hostMode?.enrolledPeers?.map { it.assignedIp }?.toSet() ?: emptySet()

/**
 * Returns a copy of this tunnel with [peer] appended to its
 * host-mode enrolledPeers list. Throws when:
 * - the tunnel has no [HostModeConfig] (programmer error: someone
 * tried to add a peer to a client tunnel),
 * - the pubkey is already in the list,
 * - the IP is already in use (caller should have detected this via
 * [HostSubnetAllocator] before calling).
 */
fun Tunnel.withEnrolledPeer(peer: EnrolledPeer): Tunnel {
    val hm = hostMode ?: throw IllegalStateException(
        "withEnrolledPeer called on a non-host-mode tunnel (id=$id)")
    if (hm.enrolledPeers.any { it.pubkeyB64 == peer.pubkeyB64 }) {
        throw IllegalStateException(
            "duplicate peer pubkey ${peer.pubkeyB64.take(12)}…")
    }
    if (hm.enrolledPeers.any { it.assignedIp == peer.assignedIp }) {
        throw IllegalStateException(
            "duplicate peer ip ${peer.assignedIp}")
    }
    return copy(hostMode = hm.copy(enrolledPeers = hm.enrolledPeers + peer))
}

/**
 * Returns a copy of this tunnel with the peer matching [pubkeyB64]
 * removed from its host-mode enrolledPeers list. No-op when:
 * - the tunnel has no [HostModeConfig], or
 * - no peer with that pubkey is currently enrolled.
 */
fun Tunnel.withoutEnrolledPeer(pubkeyB64: String): Tunnel {
    val hm = hostMode ?: return this
    val filtered = hm.enrolledPeers.filterNot { it.pubkeyB64 == pubkeyB64 }
    if (filtered.size == hm.enrolledPeers.size) return this
    return copy(hostMode = hm.copy(enrolledPeers = filtered))
}
