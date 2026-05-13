package com.gutschke.wgrtc.data

/**
 * Parse a single-peer wg-quick block into labeled fields.
 *
 * Used by the manual-config flow to render both the canonical
 * paste-able text *and* a per-field view for clients (ChromeOS,
 * some router firmwares, business-VPN setup wizards) that don't
 * accept the [Interface]/[Peer] block as a single paste — they
 * insist on separate inputs for private key, address, peer pubkey,
 * etc.
 *
 * Tolerant of extra whitespace, Windows / Unix line endings, blank
 * lines, comments starting with `#`. Anything we don't recognize
 * gets dropped from the per-field view (a multi-peer config would
 * therefore lose its second peer — but our manual-config generator
 * only ever emits single-peer). Pure — no I/O — so unit-testable.
 */
data class WgQuickFields(
    val interfacePrivateKey: String? = null,
    val interfaceAddress: String? = null,
    val interfaceDns: String? = null,
    val interfaceMtu: String? = null,
    val peerPublicKey: String? = null,
    val peerEndpoint: String? = null,
    val peerAllowedIps: String? = null,
    val peerKeepalive: String? = null,
) {
    /** Ordered list of (label, value) pairs that have a value.
     * Suitable for table-driven rendering. */
    fun named(): List<Pair<String, String>> = buildList {
        interfacePrivateKey?.let { add("Private key" to it) }
        interfaceAddress?.let { add("Address" to it) }
        interfaceDns?.let { add("DNS servers" to it) }
        interfaceMtu?.let { add("MTU" to it) }
        peerPublicKey?.let { add("Public key (host)" to it) }
        peerEndpoint?.let { add("Endpoint" to it) }
        peerAllowedIps?.let { add("Allowed IPs" to it) }
        peerKeepalive?.let { add("Persistent keepalive" to it) }
    }

    companion object {
        fun parse(wgQuickText: String): WgQuickFields {
            var section: String? = null
            var pkPriv: String? = null
            var addr: String? = null
            var dns: String? = null
            var mtu: String? = null
            var pkPub: String? = null
            var endpoint: String? = null
            var allowedIps: String? = null
            var keepalive: String? = null
            for (rawLine in wgQuickText.lineSequence()) {
                val line = rawLine.trim()
                if (line.isEmpty() || line.startsWith("#")) continue
                if (line.startsWith("[") && line.endsWith("]")) {
                    section = line.substring(1, line.length - 1).lowercase()
                    continue
                }
                val eq = line.indexOf('=')
                if (eq < 0) continue
                val key = line.substring(0, eq).trim().lowercase()
                val value = line.substring(eq + 1).trim()
                when (section) {
                    "interface" -> when (key) {
                        "privatekey" -> pkPriv = value
                        "address" -> addr = value
                        "dns" -> dns = value
                        "mtu" -> mtu = value
                    }
                    "peer" -> when (key) {
                        "publickey" -> pkPub = value
                        "endpoint" -> endpoint = value
                        "allowedips" -> allowedIps = value
                        "persistentkeepalive" -> keepalive = value
                    }
                }
            }
            return WgQuickFields(
                interfacePrivateKey = pkPriv,
                interfaceAddress = addr,
                interfaceDns = dns,
                interfaceMtu = mtu,
                peerPublicKey = pkPub,
                peerEndpoint = endpoint,
                peerAllowedIps = allowedIps,
                peerKeepalive = keepalive,
            )
        }
    }
}
