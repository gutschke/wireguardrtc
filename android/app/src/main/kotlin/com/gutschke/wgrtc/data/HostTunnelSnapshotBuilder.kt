package com.gutschke.wgrtc.data

import com.gutschke.wgrtc.signalling.IfaceAddrProvider
import com.gutschke.wgrtc.signalling.JavaIfaceAddrProvider
import com.gutschke.wgrtc.signalling.enumerateAndRank
import com.gutschke.wgrtc.signalling.formatEndpoint
import com.gutschke.wgrtc.signalling.pubKeyFromPrivate
import java.net.NetworkInterface
import java.net.Inet4Address
import java.util.Base64

/**
 * Convert a HOST_MODE [Tunnel] + a pre-allocated address into the
 * [HostTunnelSnapshot] the wormhole controller expects.
 *
 * Pulls the host's private key + listen port out of `configText`,
 * derives the matching public key, and picks a sensible LAN-side
 * endpoint string (`ip:port`) for the joiner to use as
 * `[Peer] Endpoint`. The endpoint is best-effort — once the
 * joiner persists the resulting tunnel and starts its listener,
 * the host's OFFER traffic carries the authoritative roamed
 * address and the listener-driven Endpoint rewriter takes over
 * (existing behaviour from the QR-enrolment path).
 *
 * Returns null when the tunnel isn't HOST_MODE, doesn't carry
 * required fields, or has no parseable PrivateKey / ListenPort.
 */
fun buildHostTunnelSnapshot(
    tunnel: Tunnel,
    assignedAddressCidr: String,
): HostTunnelSnapshot? {
    if (tunnel.source != Tunnel.Source.HOST_MODE) return null
    val hm = tunnel.hostMode ?: return null
    val privB64 = parseInterfaceField(tunnel.configText, "PrivateKey") ?: return null
    val listenPort = parseInterfaceField(tunnel.configText, "ListenPort")
        ?.toIntOrNull() ?: return null
    val brokerWss = tunnel.brokerWss ?: return null
    val brokerKey = tunnel.brokerKey ?: return null
    val saltB64 = tunnel.saltB64 ?: return null

    val pubB64 = try {
        Base64.getEncoder().encodeToString(
            pubKeyFromPrivate(Base64.getDecoder().decode(privB64)))
    } catch (_: Exception) { return null }

    val endpoint = pickHostEndpoint(listenPort)
    // advertise the host's WG-side IPv4 as DNS. The joiner pushes
    // this via `VpnService.Builder.addDnsServer`, so its OS resolver
    // routes UDP/53 to that address — packets cross the tunnel and the
    // host's gvisor catchall forwarder intercepts them on the port-53
    // path (regardless of dst IP) and hands them to [DnsProxy], which
    // resolves via Android's `DnsResolver`. On ChromeOS / Crostini this
    // is the difference between "the browser works" and "the user can
    // ping 1.1.1.1 but can't resolve google.com".
    val dnsIp = extractInterfaceIpv4(tunnel.configText)

    return HostTunnelSnapshot(
        tunnelId = tunnel.id,
        privKeyB64 = privB64,
        pubKeyB64 = pubB64,
        wgEndpoint = endpoint,
        // Honour the host's choice from [HostModeConfig.advertisedAllowedIps];
        // fall back to the subnet (local-only access) so legacy
        // tunnels that pre-date the field keep their behaviour.
        // Canonicalize so downstream wg-quick / SAS-payload renderers
        // never emit whitespace that ChromeOS's WG client rejects.
        allowedIps = WgAllowedIps.canonicalize(
            hm.advertisedAllowedIps ?: hm.subnet),
        assignedAddress = assignedAddressCidr,
        brokerWss = brokerWss,
        brokerKey = brokerKey,
        saltB64 = saltB64,
        hostName = tunnel.name,
        keepalive = 25,
        dns = dnsIp,
    )
}

/**
 * Extract the first IPv4 address from `[Interface] Address` (stripping
 * the CIDR suffix), or null if the field is missing / IPv6-only / can't
 * be parsed. Used by the snapshot builder to advertise the host's
 * tunnel-side IP as the joiner's DNS server ( comment).
 */
internal fun extractInterfaceIpv4(configText: String): String? {
    val raw = parseInterfaceField(configText, "Address") ?: return null
    for (part in raw.split(',')) {
        val s = part.trim().substringBefore('/')
        if (s.isEmpty()) continue
        // IPv6 contains ':' — skip; IPv4 contains '.' and only '.'.
        if (':' in s) continue
        if ('.' !in s) continue
        return s
    }
    return null
}

/**
 * Extract `<key> = <value>` from the `[Interface]` section.
 * Tolerant of indentation, extra spaces around `=`, and Unix /
 * Windows line endings. Returns the first match; subsequent
 * lines with the same key are ignored (wg-quick's own behaviour).
 */
internal fun parseInterfaceField(configText: String, key: String): String? {
    var inInterface = false
    for (rawLine in configText.lineSequence()) {
        val line = rawLine.trim()
        if (line.startsWith("#") || line.isEmpty()) continue
        if (line.startsWith("[") && line.endsWith("]")) {
            inInterface = line.equals("[Interface]", ignoreCase = true)
            continue
        }
        if (!inInterface) continue
        val eq = line.indexOf('=')
        if (eq < 0) continue
        val k = line.substring(0, eq).trim()
        if (!k.equals(key, ignoreCase = true)) continue
        return line.substring(eq + 1).trim()
    }
    return null
}

/**
 * Pick the host's wire-side endpoint as `ip:port`. Preference
 * order, mirroring [enumerateAndRank]'s LAN-first ranking:
 *
 * 1. RFC 1918 LAN address (typical hotspot/home network).
 * 2. Any non-loopback IPv4 address.
 * 3. `192.0.2.1` (TEST-NET-1) as the literal "no network" sentinel —
 * the joiner's listener will rewrite it as soon as a fresh
 * OFFER arrives, so the wrong endpoint is recoverable.
 */
internal fun pickHostEndpoint(
    listenPort: Int,
    provider: IfaceAddrProvider = JavaIfaceAddrProvider(),
): String {
    val candidates = try {
        enumerateAndRank(
            provider = provider,
            defaultIface = null,
        )
    } catch (_: Throwable) { emptyList() }
    val ip = candidates.firstOrNull { it.kind == "lan" }?.ip
        ?: candidates.firstOrNull()?.ip
        ?: pickFirstLocalIPv4()
        ?: "192.0.2.1"
    return formatEndpoint(ip, listenPort)
}

/** Last-resort: walk the JDK's NetworkInterface list ourselves. */
private fun pickFirstLocalIPv4(): String? {
    return try {
        NetworkInterface.getNetworkInterfaces().asSequence()
            .filter { it.isUp && !it.isLoopback }
            .flatMap { it.inetAddresses.asSequence() }
            .filterIsInstance<Inet4Address>()
            .filterNot { it.isLoopbackAddress }
            .map { it.hostAddress }
            .firstOrNull()
    } catch (_: Throwable) { null }
}
