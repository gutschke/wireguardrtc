package com.gutschke.wgrtc.data

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test
import java.util.Base64

/**
 * Tests for [buildHostTunnelSnapshot].
 *
 * The bug motivated this file: the snapshot builder did not
 * populate the `dns` field, so wormhole-enrolled joiners received
 * a wg-quick config with no `DNS = …` line. On ChromeOS the
 * Crostini Linux side has no resolver inside the VPN namespace
 * and name lookups silently fail (browser shows DNS errors,
 * `ping google.com` says "Name or service not known", but
 * `ping 8.8.8.8` and `telnet 1.1.1.1 80` work because TCP / ICMP
 * to literal IPs still ride the tunnel correctly).
 *
 * The fix: the host advertises its WG-side IP (the IPv4 address
 * from `[Interface] Address`) as the DNS server. Inside the host's
 * gvisor userspace NAT, UDP/53 to any destination is intercepted by
 * the catchall forwarder and routed to [DnsProxy] (which resolves via
 * Android's own DnsResolver), so the joiner's DNS works end-to-end
 * regardless of what address it thinks is upstream.
 */
class HostTunnelSnapshotBuilderTest {

    private val privKey: String =
        Base64.getEncoder().encodeToString(ByteArray(32) { 7 })

    private fun hostTunnel(addressLine: String, advertisedAllowedIps: String? = "10.99.0.0/24"): Tunnel {
        val config = """
            [Interface]
            PrivateKey = $privKey
            Address = $addressLine
            ListenPort = 51820

        """.trimIndent()
        return Tunnel(
            id = "host-id-1",
            name = "phoneA",
            configText = config,
            source = Tunnel.Source.HOST_MODE,
            brokerWss = "wss://example.org/peerjs",
            brokerKey = "kkk",
            saltB64 = "AAAA",
            hostMode = HostModeConfig(
                subnet = "10.99.0.0/24",
                advertisedAllowedIps = advertisedAllowedIps,
                enrolledPeers = emptyList(),
            ),
        )
    }

    @Test fun `dns is populated with host's WG-side IPv4`() {
        val t = hostTunnel("10.99.0.1/24")
        val s = buildHostTunnelSnapshot(t, "10.99.0.2/32")
        assertNotNull(s)
        assertEquals("10.99.0.1", s!!.dns,
            "snapshot must advertise host's tunnel-side IP as DNS so " +
                "the joiner's resolver lands at the host's gvisor catchall")
    }

    @Test fun `dns honors first IPv4 even when multiple addresses are configured`() {
        // Dual-stack host config: pick the v4 part for the DNS pointer
        // until the v6 catchall is in place (x).
        val t = hostTunnel("fdaa::1/64, 10.42.0.1/24")
        val s = buildHostTunnelSnapshot(t, "10.42.0.2/32")
        assertEquals("10.42.0.1", s!!.dns)
    }

    @Test fun `dns is null when host config has no IPv4 address`() {
        // Defensive: an IPv6-only host config can't supply a v4 DNS;
        // we leave `dns = null` so JoinerVpnService skips addDnsServer.
        // The user gets the symptom this fix is for, but the host
        // didn't have anything sensible to advertise anyway — this is
        // a "shouldn't happen in practice but don't crash" path.
        val t = hostTunnel("fdaa::1/64")
        val s = buildHostTunnelSnapshot(t, "fdaa::2/128")
        assertNull(s!!.dns)
    }

    @Test fun `joiner gets host's wg endpoint and allowed ips as usual`() {
        // Sanity check that adding the dns field didn't regress the
        // rest of the snapshot.
        val t = hostTunnel("10.99.0.1/24")
        val s = buildHostTunnelSnapshot(t, "10.99.0.5/32")!!
        assertEquals("10.99.0.5/32", s.assignedAddress)
        assertEquals("10.99.0.0/24", s.allowedIps)
        assertEquals("phoneA", s.hostName)
    }
}
