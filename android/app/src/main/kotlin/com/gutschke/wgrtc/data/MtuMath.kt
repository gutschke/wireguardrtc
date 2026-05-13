package com.gutschke.wgrtc.data

/**
 * MTU arithmetic for the WireGuard wire format. Pure functions
 * — no I/O, no state, no Android dependencies. All numbers are
 * load-bearing for real deployments; see
 * `docs/wireguard-runtime-architecture.md` §5 for the conceptual
 * write-up, and `MtuMathTest` for the test that pins each value.
 *
 * **Why we don't trust PMTU at runtime.** Path-MTU discovery
 * (RFC 1191 / 8201) signals via ICMP "fragmentation needed" /
 * "packet too big". Many production networks block one or both
 * — operators colloquially call this a "PMTU black hole." When
 * it happens, large packets with `DF=1` are dropped silently and
 * connections appear to hang. Our defense is two-layered:
 *
 * 1. **Conservative default WG MTU.** [DEFAULT_WG_MTU] = 1420
 * leaves room for a 60-byte WG-over-IPv4 envelope on a
 * standard 1500-byte path, plus a 20-byte safety margin
 * for surprise tunnels (PPPoE, GRE, carrier NAT64).
 * 2. **Active MSS clamping.** We splice [tcpMssClamp] into
 * outbound TCP SYNs, so the endpoint never *negotiates*
 * a segment size that would later require fragmentation.
 * This sidesteps PMTU entirely for the TCP majority of
 * traffic.
 *
 * The remaining 10% UDP / fragmented-IP traffic still relies on
 * the WG outer socket's `DF=0` choice to permit downstream IP
 * fragmentation; verified by [MtuDfBitTest] (instrumented).
 */
object MtuMath {

    /** Outer IP family the WG packets travel under. */
    enum class OuterFamily { IPV4, IPV6 }

    /** IP family of the payload the tunnel carries. */
    enum class InnerFamily { IPV4, IPV6 }

    /**
     * Per-packet bytes added by the WireGuard transport
     * encapsulation when the outer is [outer].
     *
     * IPv4 outer: 20 (IP) + 8 (UDP) + 32 (WG framing + AEAD) = 60
     * IPv6 outer: 40 (IP) + 8 (UDP) + 32 (WG framing + AEAD) = 80
     *
     * The 32-byte WG portion is fixed: 16-byte transport-data
     * header (type / receiver index / counter) + 16-byte
     * Poly1305 authenticator.
     */
    fun wgOverhead(outer: OuterFamily): Int = when (outer) {
        OuterFamily.IPV4 -> 20 + 8 + 32
        OuterFamily.IPV6 -> 40 + 8 + 32
    }

    /**
     * Conservative inner MTU we hand the WG interface, given the
     * outer path's MTU. Reserves a 20-byte safety margin on top
     * of the raw overhead so surprises (PPPoE, GRE wrappers,
     * mid-path NAT64) don't push us over. Throws when the path
     * is too narrow to support a useful tunnel.
     */
    fun safeWgMtu(physicalMtu: Int, outer: OuterFamily): Int {
        require(physicalMtu > 0) { "physicalMtu must be > 0 (got $physicalMtu)" }
        val raw = physicalMtu - wgOverhead(outer) - SAFETY_MARGIN
        require(raw >= MIN_USEFUL_MTU) {
            "computed wg MTU $raw < MIN_USEFUL_MTU $MIN_USEFUL_MTU; " +
                "physical path is too narrow for a useful tunnel"
        }
        return raw
    }

    /**
     * TCP MSS to advertise / clamp on outbound SYNs traversing
     * the tunnel. Equals `wgMtu - innerIpHeader - tcpHeader`,
     * floored at [TCP_MSS_FLOOR] (RFC 1122 §3.3.3 / §4.2.2.6:
     * every IPv4 implementation must accept 536-byte segments
     * without prior negotiation).
     */
    fun tcpMssClamp(wgMtu: Int, innerFamily: InnerFamily): Int {
        require(wgMtu > 0) { "wgMtu must be > 0 (got $wgMtu)" }
        val ipHeader = when (innerFamily) {
            InnerFamily.IPV4 -> 20
            InnerFamily.IPV6 -> 40
        }
        val raw = wgMtu - ipHeader - 20 // 20-byte TCP header
        return raw.coerceAtLeast(TCP_MSS_FLOOR)
    }

    /**
     * Default WG-side MTU used by [WgQuickUapi] rendering and
     * by [Tunnel] when nothing tunnel-specific is set. Equals
     * `safeWgMtu(1500, IPv4)` — pinned redundantly so a casual
     * edit to one hits a test failure at the other.
     */
    const val DEFAULT_WG_MTU: Int = 1420

    /** Floor below which we refuse to compute a tunnel MTU.
     * 576 is IPv4's minimum-reassembly-buffer guarantee from
     * RFC 1122 — any conforming IPv4 host can receive this. */
    const val MIN_USEFUL_MTU: Int = 576

    /** Safety margin subtracted from the raw overhead-adjusted
     * size. Absorbs unexpected mid-path encapsulation (PPPoE
     * +8, GRE +24, carrier NAT64 ~10-20). */
    const val SAFETY_MARGIN: Int = 20

    /** RFC 1122 mandated minimum that all IPv4 implementations
     * accept without negotiation. Floor for [tcpMssClamp]. */
    const val TCP_MSS_FLOOR: Int = 536
}
