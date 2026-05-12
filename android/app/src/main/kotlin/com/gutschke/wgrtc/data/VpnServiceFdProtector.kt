package com.gutschke.wgrtc.data

/**
 * Adapter from a `(Int) -> Boolean` protect-fd lambda to
 * [WgFdProtector]. The lambda typically points at a running
 * [android.net.VpnService.protect] — the only way to make the
 * wire-side WG socket bypass any OTHER active VPN.
 *
 * Pulled out of the service class so unit tests can inject a fake
 * lambda without needing Robolectric or an Android framework jar.
 */
class VpnServiceFdProtector(
    private val protect: (Int) -> Boolean,
) : WgFdProtector {
    override fun protect(fd: Int): Boolean = this.protect.invoke(fd)
}
