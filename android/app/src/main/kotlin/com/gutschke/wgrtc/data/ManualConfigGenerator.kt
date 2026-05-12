package com.gutschke.wgrtc.data

import com.gutschke.wgrtc.signalling.pubKeyFromPrivate
import java.security.SecureRandom
import java.util.Base64

/**
 * Generate a wg-quick config block for a peer that can't run
 * wgrtc-android (e.g. ChromeOS clients that go through the
 * Play-Store-installed WireGuard app, or any standard wg client).
 *
 * Workflow:
 * 1. Caller picks the next free IP via [HostSubnetAllocator].
 * 2. [generate] mints a fresh keypair for the joiner and renders
 * a complete `[Interface]` + `[Peer]` block.
 * 3. UI displays the block as both copy-paste text and a QR.
 * 4. Caller persists the new peer (via [ListenerHub.applyWormholePeer]
 * or equivalent) so the host's wg-go starts accepting handshakes
 * from this pubkey.
 *
 * **Security note**: this generator produces a *complete* private
 * key inside the wg-quick text — the joiner's identity material
 * lives both on the phone (for QR rendering) and on the
 * destination device. Treat the resulting blob like any other
 * private-key-bearing artefact: don't pipe it through arbitrary
 * networks, don't keep it on the phone after delivery, and don't
 * log it. The HTTP-server companion ([ManualConfigServer]) gates
 * delivery behind a single-use token + 60 s TTL for that reason.
 */
object ManualConfigGenerator {

    /** Produce a wg-quick config + the EnrolledPeer record needed
     * to register the joiner on the host's tunnel. */
    fun generate(
        snapshot: HostTunnelSnapshot,
        deviceLabel: String = "manual-peer",
        rng: SecureRandom = SecureRandom(),
    ): Result {
        val priv = ByteArray(32).also { rng.nextBytes(it) }
        priv[0] = (priv[0].toInt() and 0xf8).toByte()
        priv[31] = ((priv[31].toInt() and 0x7f) or 0x40).toByte()
        val pubBytes = pubKeyFromPrivate(priv)
        val privB64 = Base64.getEncoder().encodeToString(priv)
        val pubB64 = Base64.getEncoder().encodeToString(pubBytes)

        val configText = buildString {
            append("[Interface]\n")
            append("PrivateKey = ").append(privB64).append('\n')
            append("Address = ").append(snapshot.assignedAddress).append('\n')
            snapshot.dns?.let { append("DNS = ").append(it).append('\n') }
            snapshot.mtu?.let { append("MTU = ").append(it).append('\n') }
            append("\n[Peer]\n")
            append("PublicKey = ").append(snapshot.pubKeyB64).append('\n')
            append("Endpoint = ").append(snapshot.wgEndpoint).append('\n')
            // ChromeOS's WG client rejects whitespace inside AllowedIPs.
            // Canonicalize even though the snapshot field is supposed
            // to be clean already — defence in depth, since the field
            // ultimately originates from a user textbox.
            append("AllowedIPs = ")
                .append(WgAllowedIps.canonicalize(snapshot.allowedIps))
                .append('\n')
            snapshot.keepalive?.let {
                append("PersistentKeepalive = ").append(it).append('\n')
            }
        }.trimEnd('\n')

        val ip = snapshot.assignedAddress.substringBefore('/')
        return Result(
            wgQuickText = configText,
            joinerPeer = HostWormholeResult(
                tunnelId = snapshot.tunnelId,
                joinerPubkeyB64 = pubB64,
                joinerIp = ip,
                joinerNameHint = deviceLabel,
                // persist the wg-quick text on the EnrolledPeer
                // so the host UI can re-display it after a process
                // restart without losing the joiner's privkey.
                manualInvitationText = configText,
            ),
        )
    }

    data class Result(
        /** Complete wg-quick config text the joiner pastes into
         * their WG client. */
        val wgQuickText: String,
        /** Persistence-shaped record the host's UI commits via
         * [com.gutschke.wgrtc.WgrtcViewModel.addWormholeEnrolledPeer]. */
        val joinerPeer: HostWormholeResult,
    )
}
