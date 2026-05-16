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

        /**
         * If the joiner's `addresses` include any IPv6 entry but
         * `dnsServers` is v4-only, return a copy of `dnsServers`
         * with a synthesized v6 DNS appended.  Otherwise return
         * `dnsServers` unchanged.
         *
         * **Why this exists.**  Android's resolver applies
         * `AI_ADDRCONFIG`-style filtering to `getaddrinfo` results:
         * when the active network has no v6 DNS server, AAAA records
         * are silently dropped even if the underlying transport
         * does carry v6.  A wg-quick config that lists
         * `DNS = 1.1.1.1` plus a dual-stack
         * `Address = 10.x/32, fd00::6/128` therefore loses v6 name
         * resolution from inside the tunnel — the user sees
         * "no v6" even though `nc -6 <literal>` works end-to-end.
         * Surfaced by a real-device test from a Pixel hotspot.
         *
         * **Choice of v6 DNS.**  We pick a server in the same
         * provider family as the user's existing v4 DNS so we don't
         * silently introduce a new third party.  Cloudflare /
         * Google / Quad9 mappings are hard-coded; the fallback for
         * unknown providers is Cloudflare's `2606:4700:4700::1111`,
         * matching wgrtc's existing `1.1.1.1` baseline.
         *
         * If the user already has a v6 DNS in their config, we
         * touch nothing.
         */
        fun dnsWithV6Fallback(
            addresses: List<Cidr>,
            dnsServers: List<String>,
        ): List<String> {
            val hasV6Address = addresses.any { it.address.contains(':') }
            if (!hasV6Address) return dnsServers
            val hasV6Dns = dnsServers.any { it.contains(':') }
            if (hasV6Dns) return dnsServers
            if (dnsServers.isEmpty()) return dnsServers  // user opted out entirely
            return dnsServers + synthesizeV6Dns(dnsServers)
        }

        private fun synthesizeV6Dns(existingDns: List<String>): String = when {
            existingDns.any { it == "1.1.1.1" || it == "1.0.0.1" } ->
                "2606:4700:4700::1111"
            existingDns.any { it == "8.8.8.8" || it == "8.8.4.4" } ->
                "2001:4860:4860::8888"
            existingDns.any { it == "9.9.9.9" || it == "149.112.112.112" } ->
                "2620:fe::fe"
            // Unknown provider — fall back to Cloudflare, matching
            // wgrtc's de-facto v4 default of 1.1.1.1.
            else -> "2606:4700:4700::1111"
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
