package com.gutschke.wgrtc.data

import java.util.Base64

/**
 * Pure-function renderer: produce a wireguard-tools UAPI string
 * suitable for [WgBridgeBackend.configureUapi] from a host-mode
 * tunnel's private key + enrolled peers.
 *
 * UAPI format (one key=value per line):
 *
 * private_key=<32-byte-hex>
 * listen_port=<int>
 * public_key=<32-byte-hex>
 * allowed_ip=<cidr>
 * public_key=<...> (repeated for each peer)
 * allowed_ip=<...>
 *
 * Differs from wg-quick `.conf` in two ways:
 * - keys are HEX, not standard-base64.
 * - sections aren't bracketed — each `public_key=` starts a new
 * peer block.
 *
 * Pulled out of [HostModeRunner] so the conversion is unit-tested
 * separately and is reusable by future test harnesses.
 */
object HostModeUapi {

    /**
     * @param privateKeyB64 standard-base64 32-byte WG private key
     * (as stored in the tunnel's `[Interface]
     * PrivateKey =` line).
     * @param listenPort UDP port the wire-side socket binds.
     * @param peers per-peer (pubkey-base64, allowed-ip-cidr).
     * @param replacePeers when true, prefixes the peer set with
     * `replace_peers=true` so wireguard-go drops any peers
     * that were in the device but aren't in [peers]. REQUIRED
     * for reconfigures after a revoke — without it the merge
     * semantics of `IpcSet` keep stale peers alive in the
     * wg-go table indefinitely (observed: revoked-peer
     * ChromeOS still showed Connected because the old
     * session persisted on the host side). Initial starts
     * usually pass false because the device is empty
     * anyway, but `true` is harmless there.
     */
    fun render(
        privateKeyB64: String,
        listenPort: Int,
        peers: List<Peer>,
        replacePeers: Boolean = false,
    ): String {
        val sb = StringBuilder()
        sb.append("private_key=").append(b64ToHex(privateKeyB64)).append('\n')
        sb.append("listen_port=").append(listenPort).append('\n')
        if (replacePeers) sb.append("replace_peers=true\n")
        for (p in peers) {
            sb.append("public_key=").append(b64ToHex(p.publicKeyB64)).append('\n')
            sb.append("allowed_ip=").append(p.allowedIp).append('\n')
            // V6.3 — emit a second allowed_ip line for the peer's
            // v6 sibling when present.  wg-go's UAPI accepts
            // multiple allowed_ip= lines per peer (additive); both
            // get installed in the kernel WG allowed-IPs filter.
            p.allowedIpV6?.let {
                sb.append("allowed_ip=").append(it).append('\n')
            }
        }
        return sb.toString()
    }

    data class Peer(
        val publicKeyB64: String,
        val allowedIp: String,
        /** V6.3 — per-peer v6 CIDR, e.g. `fd00::2/128`.  Null on
         * peers persisted before V6.2 or on tunnels with no
         * subnetV6.  When non-null, a second `allowed_ip=` UAPI
         * line is emitted so wireguard-go's filter accepts both
         * families from this peer. */
        val allowedIpV6: String? = null,
    )

    private fun b64ToHex(b64: String): String {
        val bytes = Base64.getDecoder().decode(b64)
        val out = StringBuilder(bytes.size * 2)
        for (b in bytes) {
            val v = b.toInt() and 0xff
            out.append(HEX[v ushr 4]).append(HEX[v and 0x0f])
        }
        return out.toString()
    }

    private val HEX = "0123456789abcdef".toCharArray()
}
