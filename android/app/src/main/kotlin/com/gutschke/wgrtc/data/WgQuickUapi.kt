package com.gutschke.wgrtc.data

import java.util.Base64

/**
 * Convert a wg-quick `.conf` text block (joiner-side, with one or
 * more `[Peer]` blocks that include `Endpoint = ...`) into the UAPI
 * string wireguard-go's `IpcSet` consumes.
 *
 * **Why this exists.** The Kotlin↔Go bridge speaks UAPI text
 * (see `docs/wireguard-runtime-architecture.md` §4). This
 * converter lets the rest of the app keep the human-friendly
 * wg-quick text format and have a single canonical place where
 * the translation to UAPI happens.
 *
 * **Format target — UAPI.** Line-oriented `key=value` document.
 * Keys that wireguard-go knows live in two scopes:
 *
 * - **Device-scope** (lines before the first `public_key=`):
 * `private_key`, `listen_port`, `fwmark`, `replace_peers`.
 * - **Peer-scope** (lines following each `public_key=`):
 * `endpoint`, `allowed_ip` (repeated for each entry),
 * `persistent_keepalive_interval`, `replace_allowed_ips`,
 * `remove`, `update_only`.
 *
 * **`replace_peers=true` / `replace_allowed_ips=true` are emitted
 * unconditionally** — without them, `IpcSet` is a *merge* and a
 * reconfigure (e.g. user edits AllowedIPs to widen routing) would
 * leave the previous values lingering in wireguard-go's table.
 * Same reasoning as for the host side.
 *
 * Keys we don't translate (intentionally): `Address`, `DNS`, `MTU`,
 * `Table`, `PreUp` / `PreDown` / `PostUp` / `PostDown`. Those are
 * wg-quick userspace conventions; wireguard-go only cares about the
 * crypto + routing trie. Address + MTU are applied at TUN-fd
 * creation time by the caller (Android's `VpnService.Builder`),
 * not via UAPI.
 */
object WgQuickUapi {

    /**
     * @return UAPI text suitable for `bridge.configureUapi(...)`.
     * @throws IllegalArgumentException if `[Interface] PrivateKey` is missing
     * or any base64 key fails to decode to 32 bytes.
     */
    fun render(wgQuickText: String): String {
        var section: String? = null
        var ifPriv: String? = null
        var ifListenPort: Int? = null
        // Per-peer accumulator. Flushed each time we see a new
        // [Peer] section header (or end-of-document).
        val peers = mutableListOf<PeerUapi>()
        var curPeer: PeerInProgress? = null

        fun flushPeer() {
            curPeer?.let {
                val pubB64 = it.publicKey
                    ?: throw IllegalArgumentException("[Peer] missing PublicKey")
                peers += PeerUapi(
                    publicKeyB64 = pubB64,
                    endpoint = it.endpoint,
                    keepalive = it.keepalive,
                    allowedIps = it.allowedIps,
                )
            }
            curPeer = null
        }

        for (rawLine in wgQuickText.lineSequence()) {
            val line = rawLine.trim().substringBefore('#').trim()
            if (line.isEmpty()) continue
            if (line.startsWith("[") && line.endsWith("]")) {
                if (section == "peer") flushPeer()
                section = line.substring(1, line.length - 1).lowercase()
                if (section == "peer") curPeer = PeerInProgress()
                continue
            }
            val eq = line.indexOf('=')
            if (eq < 0) continue
            val key = line.substring(0, eq).trim().lowercase()
            val value = line.substring(eq + 1).trim()
            when (section) {
                "interface" -> when (key) {
                    "privatekey" -> ifPriv = value
                    "listenport" -> ifListenPort = value.toIntOrNull()
                }
                "peer" -> {
                    val cp = curPeer ?: continue
                    when (key) {
                        "publickey" -> cp.publicKey = value
                        "endpoint" -> cp.endpoint = value
                        "persistentkeepalive" -> cp.keepalive = value.toIntOrNull()
                        "allowedips" -> {
                            // Comma-separated; preserve order.
                            for (entry in value.split(',')) {
                                val v = entry.trim()
                                if (v.isNotEmpty()) cp.allowedIps += v
                            }
                        }
                    }
                }
            }
        }
        flushPeer()

        if (ifPriv == null) {
            throw IllegalArgumentException("[Interface] PrivateKey is required")
        }

        val sb = StringBuilder()
        sb.append("private_key=").append(b64ToHex(ifPriv)).append('\n')
        ifListenPort?.let { sb.append("listen_port=").append(it).append('\n') }
        sb.append("replace_peers=true\n")
        for (p in peers) {
            sb.append("public_key=").append(b64ToHex(p.publicKeyB64)).append('\n')
            p.endpoint?.let { sb.append("endpoint=").append(it).append('\n') }
            // wireguard-go only initiates a handshake when it has
            // outbound traffic to encrypt (or when keepalive fires).
            // The candidate race calls setEndpoint and then polls
            // for a handshake, but it doesn't generate any tun
            // traffic itself — so a peer config that omits
            // PersistentKeepalive deadlocks the race even when the
            // endpoint is fully reachable. Enrollment-emitted
            // configs always set 25 explicitly; this fallback keeps
            // manually-imported configs (no keepalive line) working
            // through the same code path. An explicit `= 0` is
            // preserved so users who really want no keepalive can
            // still opt out.
            val effectiveKeepalive = p.keepalive ?: if (p.endpoint != null) DEFAULT_KEEPALIVE_SECONDS else null
            effectiveKeepalive?.let {
                sb.append("persistent_keepalive_interval=").append(it).append('\n')
            }
            sb.append("replace_allowed_ips=true\n")
            for (cidr in p.allowedIps) {
                sb.append("allowed_ip=").append(cidr).append('\n')
            }
        }
        return sb.toString()
    }

    private const val DEFAULT_KEEPALIVE_SECONDS = 25

    private data class PeerUapi(
        val publicKeyB64: String,
        val endpoint: String?,
        val keepalive: Int?,
        val allowedIps: List<String>,
    )

    private class PeerInProgress {
        var publicKey: String? = null
        var endpoint: String? = null
        var keepalive: Int? = null
        val allowedIps: MutableList<String> = mutableListOf()
    }

    private fun b64ToHex(b64: String): String {
        val bytes = try { Base64.getDecoder().decode(b64) }
            catch (e: IllegalArgumentException) {
                throw IllegalArgumentException("invalid base64 key: '$b64'", e)
            }
        if (bytes.size != 32) {
            throw IllegalArgumentException(
                "WG keys must decode to 32 bytes; got ${bytes.size} from '$b64'")
        }
        val sb = StringBuilder(64)
        for (b in bytes) {
            val v = b.toInt() and 0xff
            sb.append(HEX[v ushr 4]).append(HEX[v and 0x0f])
        }
        return sb.toString()
    }

    private val HEX = "0123456789abcdef".toCharArray()
}
