package com.gutschke.wgrtc.data

import com.gutschke.wgrtc.signalling.pubKeyFromPrivate
import java.security.SecureRandom
import java.util.Base64
import java.util.UUID

/**
 * Mints a fresh host-mode tunnel from user-supplied
 * parameters: generates a WG keypair + 32-byte salt, renders the
 * `[Interface]` block, and packages everything into a [Tunnel] with
 * `Source.HOST_MODE` and an empty [HostModeConfig].
 *
 * Pure JVM — no Android dependencies — so the same code path runs
 * under `:app:test`. Caller is responsible for persisting the
 * returned tunnel via [TunnelStore]; once persisted,
 * [com.gutschke.wgrtc.data.ListenerHub.reconcileFromStore] will
 * pick it up and start a host-mode listener.
 *
 * The 32-byte salt matches what the daemon and
 * [com.gutschke.wgrtc.signalling.routingId] expect, and the same
 * encoding ([Base64.getUrlEncoder] no padding) the URI spec uses —
 * so the salt round-trips through QR codes without re-encoding.
 */
object HostModeFactory {

    /**
     * @param name display name for the tunnel
     * @param subnet CIDR pool for client IPs (e.g., "10.99.0.0/24")
     * @param hostIp the host's address in [subnet] (e.g., "10.99.0.1");
     * must lie inside [subnet]
     * @param listenPort UDP port wg-go binds (1-65535)
     * @param brokerWss `wss://...` URL of the PeerJS broker
     * @param brokerKey API key the broker requires
     */
    fun newTunnel(
        name: String,
        subnet: String,
        hostIp: String,
        listenPort: Int,
        brokerWss: String,
        brokerKey: String,
        /** What joiners route through the tunnel. Null = subnet
         * only (local-only access). See [HostModeConfig.advertisedAllowedIps]. */
        advertisedAllowedIps: String? = null,
        rng: SecureRandom = SecureRandom(),
    ): Tunnel {
        require(listenPort in 1..65535) {
            "listenPort out of range: $listenPort"
        }
        // Validate subnet + host membership via the same allocator the
        // runtime uses — keeps "well-formed subnet" semantics consistent.
        // nextFreeIp returns null on malformed input or host-not-in-subnet.
        val probe = HostSubnetAllocator.nextFreeIp(subnet, hostIp, emptySet())
        if (probe == null) {
            // Distinguish the two failure modes for a clearer error.
            // (Caller likely typoed the subnet or the host IP.)
            throw IllegalArgumentException(
                "subnet ($subnet) is malformed, or hostIp ($hostIp) doesn't fall inside it")
        }

        // 32-byte WG private key. Conventional clamping (0xF8 / 0x7F /
        // 0x40 bit-twiddling) is applied internally by libsodium's X25519
        // when the key is used; we don't pre-clamp here so the bytes
        // round-trip through wg-quick parsers unchanged.
        val privBytes = ByteArray(32).also { rng.nextBytes(it) }
        val privB64 = Base64.getEncoder().encodeToString(privBytes)
        // Salt: 32 bytes URL-safe-base64 no padding — matches what the
        // routing-id calc expects and what the wgrtc-enroll URI spec
        // emits.
        val saltBytes = ByteArray(32).also { rng.nextBytes(it) }
        val saltB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(saltBytes)

        val prefix = subnet.substringAfter('/').trim()
        val configText = buildString {
            append("[Interface]\n")
            append("PrivateKey = ").append(privB64).append('\n')
            append("Address = ").append(hostIp).append('/').append(prefix).append('\n')
            append("ListenPort = ").append(listenPort).append('\n')
        }.trimEnd('\n')

        return Tunnel(
            id = UUID.randomUUID().toString(),
            name = name,
            configText = configText,
            source = Tunnel.Source.HOST_MODE,
            brokerWss = brokerWss,
            brokerKey = brokerKey,
            saltB64 = saltB64,
            hostMode = HostModeConfig(
                subnet = subnet,
                enrolledPeers = emptyList(),
                advertisedAllowedIps = advertisedAllowedIps,
            ),
        )
    }
}
