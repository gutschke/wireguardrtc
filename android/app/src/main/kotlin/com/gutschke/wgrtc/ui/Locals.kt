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
val LocalDisconnect = compositionLocalOf<() -> Unit> {
    error("LocalDisconnect not provided")
}
