package com.gutschke.wgrtc.ui

import androidx.compose.runtime.compositionLocalOf

/**
 * Connect/disconnect requires the calling Activity (it has to launch
 * `VpnService.prepare(...)`). We let the `MainActivity` install these
 * callbacks via a CompositionLocal so screens stay free of Activity
 * references.
 */
val LocalConnect = compositionLocalOf<(String) -> Unit> {
    error("LocalConnect not provided")
}
/** Disconnect a specific tunnel by id.  Per-tunnel since D4.H2 —
 * before then the app could only have one tunnel up at a time so
 * "the active tunnel" was unambiguous, but with N concurrent host
 * tunnels the UI needs to say which one to bring down. */
val LocalDisconnect = compositionLocalOf<(String) -> Unit> {
    error("LocalDisconnect not provided")
}
