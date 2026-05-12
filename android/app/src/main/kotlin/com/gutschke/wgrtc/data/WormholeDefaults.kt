package com.gutschke.wgrtc.data

/**
 * Default broker coordinates for the wormhole-code flow.
 *
 * Both sides of a wormhole exchange MUST use the same broker; the
 * code itself doesn't carry broker info (that would defeat the
 * short-code UX). The default below points at the public PeerJS
 * broker — pick a different one by editing this constant or
 * (eventually) a settings screen.
 *
 * **Why these values**: `0.peerjs.com` is the public PeerJS service.
 * The `peerjs` key is its standard API key. The custom-broker case
 * (e.g. self-hosted at `wss://example.org/...`) is supported by
 * just changing this constant — no protocol or wire-format change.
 *
 * Future: surface this via [com.gutschke.wgrtc.WgrtcViewModel]'s
 * settings store so a user can switch brokers without rebuilding.
 */
object WormholeDefaults {
    const val BROKER_WSS: String = "wss://0.peerjs.com/peerjs"
    const val BROKER_KEY: String = "peerjs"
}
