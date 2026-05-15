package com.gutschke.wgrtc.data

import com.gutschke.wgrtc.service.JoinerNVpnService

/**
 * Adapts one joiner slot inside a [JoinerNVpnService] to the
 * [JoinerEndpointReconfigurer] surface that [WgBridgeTunnelEndpointController]
 * already targets. Lets the existing candidate-race / endpoint-roam
 * plumbing drive the multi-joiner backend with no per-call branching.
 *
 * The adapter holds no state of its own — the joiner has already
 * been added to the service via `service.addJoiner(...)` before this
 * is constructed, and `close()` calls back through to
 * `service.removeJoiner(...)` so the underlying [JoinerNController]
 * decides whether to tear down the whole shared stack (last joiner)
 * or just drop one slot.
 *
 * **`reconfigure(wgQuickConfig)`** renders the wg-quick text into
 * UAPI and pushes it via [JoinerNVpnService.reconfigure]. The shared
 * stack reuses the existing bridge handle — no Builder rebuild.
 *
 * **`snapshotStats()`** asks the service for the slot's UAPI dump
 * and parses it the same way [JoinerWgRunner] does. Null when the
 * joiner is no longer in the slot map.
 *
 * **`close()`** is idempotent — removing a missing slot is a no-op
 * in [JoinerNController]. Catches throw because the disconnect path
 * already handles a wider failure; an exception here would mask the
 * outer error.
 */
class JoinerNEndpointReconfigurer(
    private val service: JoinerNVpnService,
    private val tunnelId: String,
) : JoinerEndpointReconfigurer {

    override fun reconfigure(wgQuickConfig: String) {
        service.reconfigure(tunnelId, WgQuickUapi.render(wgQuickConfig))
    }

    override fun snapshotStats(): UapiStats? {
        val raw = try { service.snapshotUapi(tunnelId) } catch (_: Throwable) { return null }
        if (raw.isNullOrEmpty()) return null
        return UapiStatsParser.parse(raw)
    }

    override fun close() {
        try { service.removeJoiner(tunnelId) } catch (_: Throwable) {}
    }
}
