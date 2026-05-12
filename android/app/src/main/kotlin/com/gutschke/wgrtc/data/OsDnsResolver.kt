package com.gutschke.wgrtc.data

import android.net.Network
import java.net.InetAddress
import java.net.UnknownHostException

/**
 * Production [DnsResolver] backed by the phone's OS resolver.
 *
 * When [network] is null we use `InetAddress.getAllByName(name)`
 * — the OS default resolver, honoring whatever DNS the phone is
 * currently configured to use (system, MDNS, DoH if upgraded).
 *
 * When [network] is non-null (set by 's `EgressSelector` once
 * we wire it up) we call `network.getAllByName(name)` instead,
 * so the DNS lookup egresses through that specific Android
 * [Network]. This matters for the cellular-only / cascade-tunnel
 * cases: the *DNS* part of a flow must also go through the
 * chosen egress, otherwise a phone on WiFi would leak the
 * joiner's lookups via the WiFi resolver even when the user
 * pinned the data path to cellular.
 *
 * Lookups block on a worker thread; on-platform `InetAddress`
 * does its own retries / timeouts (Android: ~5s default per
 * server, two tries each). We don't add our own timeout here —
 * the joiner client sees either a timely answer, or the WG
 * tunnel times out the UDP roundtrip on its end.
 */
class OsDnsResolver(
    private val network: Network? = null,
) : DnsResolver {

    @Throws(UnknownHostException::class)
    override fun resolve(name: String): List<InetAddress> {
        val cleaned = name.trim().trim('.').lowercase()
        if (cleaned.isEmpty()) throw UnknownHostException("empty name")
        val all = if (network != null) network.getAllByName(cleaned)
                  else InetAddress.getAllByName(cleaned)
        return all?.toList() ?: emptyList()
    }
}
