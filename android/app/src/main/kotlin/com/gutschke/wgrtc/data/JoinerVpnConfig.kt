package com.gutschke.wgrtc.data

/**
 * A CIDR address — `address` plus a `prefixLen` (e.g. /24 = 24).
 * Plain Strings rather than `InetAddress` because Android's
 * `VpnService.Builder.addAddress` / `addRoute` overloads take
 * String + Int, and this class isn't expected to do any networking
 * itself.
 */
data class Cidr(val address: String, val prefixLen: Int)

/**
 * The bits a `VpnService.Builder` needs from a wg-quick `.conf`.
 *
 * Distinct from [WgQuickUapi]'s output (which targets
 * `wireguard-go`'s IpcSet) because the Builder API speaks IP
 * addresses + routes + MTU, not crypto keys. Both are derived
 * from the same source text by separate walks; doing it as one
 * pass would conflate two unrelated concerns and make each harder
 * to test.
 *
 * `addresses` are the local TUN addresses (from `[Interface]
 * Address = ...`). `routes` are CIDRs that should route THROUGH
 * the TUN (from each `[Peer] AllowedIPs = ...`). `mtu` defaults
 * to [MtuMath.DEFAULT_WG_MTU] when `[Interface] MTU` is absent.
 */
data class JoinerVpnConfig(
    val addresses: List<Cidr>,
    val routes: List<Cidr>,
    val mtu: Int,
    /** Pushed via `VpnService.Builder.addDnsServer` so the OS resolver
     * inside the VPN namespace knows where to send name lookups. On
     * the host these UDP/53 packets get caught by the gvisor netstack's
     * catchall UDP forwarder and routed to [DnsProxy] (so the actual
     * resolver above is the host's Android `DnsResolver`, regardless of
     * which DNS IP the joiner thinks it is talking to). Empty list →
     * no DNS pushed; ChromeOS / Crostini will fall back to whatever it
     * has, which is usually wrong inside a VPN namespace. */
    val dnsServers: List<String> = emptyList(),
) {
    companion object {
        /** Default WG MTU. Single source of truth for the
         * number — see [MtuMath.DEFAULT_WG_MTU] for the
         * derivation and `MtuMathTest` for the test that pins
         * it. */
        const val DEFAULT_MTU = MtuMath.DEFAULT_WG_MTU

        /**
         * Parse the wg-quick text. Returns the addresses, routes,
         * and MTU. Throws `IllegalArgumentException` if no
         * `[Interface] Address` is present (joiner can't bring up
         * a TUN with no local address — Builder.establish would
         * throw an opaque error).
         */
        fun parse(wgQuickText: String): JoinerVpnConfig {
            var section: String? = null
            val addresses = mutableListOf<Cidr>()
            val routes = mutableListOf<Cidr>()
            val dnsServers = mutableListOf<String>()
            var mtu: Int? = null
            // first [Peer] Endpoint line we see — used to
            // pick the family-aware default MTU when the user
            // didn't override.  We don't try to handle multi-peer
            // configs with mixed-family endpoints; pick the first.
            var firstPeerEndpoint: String? = null

            for (rawLine in wgQuickText.lineSequence()) {
                val line = rawLine.trim().substringBefore('#').trim()
                if (line.isEmpty()) continue
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
                        "address" -> for (part in value.split(',')) {
                            val s = part.trim()
                            if (s.isNotEmpty()) addresses += parseCidr(s)
                        }
                        "mtu" -> mtu = value.toIntOrNull()
                        "dns" -> for (part in value.split(',')) {
                            val s = part.trim()
                            if (s.isNotEmpty()) dnsServers += s
                        }
                    }
                    "peer" -> when (key) {
                        "allowedips" -> for (part in value.split(',')) {
                            val s = part.trim()
                            if (s.isNotEmpty()) routes += parseCidr(s)
                        }
                        "endpoint" -> if (firstPeerEndpoint == null) {
                            firstPeerEndpoint = value
                        }
                    }
                }
            }

            if (addresses.isEmpty()) {
                throw IllegalArgumentException("[Interface] Address is required")
            }
            // when the user didn't set MTU explicitly,
            // pick 1420 for v4 endpoints and 1400 for v6.  A
            // missing Endpoint (passive peer) falls back to v4 —
            // matches pre-V6 behavior.
            val effectiveMtu = mtu ?: run {
                val outer = firstPeerEndpoint?.let { MtuMath.inferOuterFamily(it) }
                    ?: MtuMath.OuterFamily.IPV4
                MtuMath.defaultWgMtu(outer)
            }
            return JoinerVpnConfig(
                addresses = addresses,
                routes = routes,
                mtu = effectiveMtu,
                dnsServers = dnsServers,
            )
        }

        /** Tolerant CIDR parser. `1.2.3.4/24` → Cidr(...,24).
         * Bare `1.2.3.4` → /32. Bare `fd00::1` → /128. */
        private fun parseCidr(s: String): Cidr {
            val slash = s.indexOf('/')
            if (slash < 0) {
                val isV6 = s.contains(':')
                return Cidr(s, if (isV6) 128 else 32)
            }
            val addr = s.substring(0, slash)
            val len = s.substring(slash + 1).toIntOrNull()
                ?: throw IllegalArgumentException("invalid prefix in '$s'")
            return Cidr(addr, len)
        }
    }
}
