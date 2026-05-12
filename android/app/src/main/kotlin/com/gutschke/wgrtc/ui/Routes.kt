package com.gutschke.wgrtc.ui

object Routes {
    const val LIST = "list"
    const val ADD = "add"
    /** Join-method picker (scan / wormhole / paste / manual). */
    const val JOIN = "add/join"
    const val PASTE = "add/paste"
    const val SCAN = "add/scan"
    const val MANUAL = "add/manual"
    /** host-mode setup form. */
    const val HOST_SETUP = "add/host"
    /** wormhole-code initiator (joining-client) screen. */
    const val WORMHOLE_JOIN = "add/wormhole/join"
    /** wormhole-code responder (host) screen. Parameterised
     * by the host tunnel's id so the controller can build a
     * HostTunnelSnapshot. */
    const val WORMHOLE_HOST = "wormhole/host/{tunnelId}"
    fun wormholeHost(tunnelId: String) = "wormhole/host/$tunnelId"
    /** App-level settings (default broker, …). */
    const val SETTINGS = "settings"
    /** Three-page first-launch tour. */
    const val ONBOARDING = "onboarding"
    /** About / acknowledgements. */
    const val ABOUT = "about"
    /** detail/{tunnelId} */
    const val DETAIL = "detail/{tunnelId}"
    fun detail(id: String) = "detail/$id"
    /** edit/{tunnelId} — full tunnel-edit form. */
    const val EDIT = "edit/{tunnelId}"
    fun edit(id: String) = "edit/$id"
    /** diagnostics/{tunnelId} — per-tunnel ping / traceroute. */
    const val DIAGNOSTICS = "diagnostics/{tunnelId}"
    fun diagnostics(id: String) = "diagnostics/$id"
}
