package com.gutschke.wgrtc.ui.components

import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.State
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.remember
import kotlinx.coroutines.delay

/**
 * Returns a [State]<Long> that re-emits `System.currentTimeMillis()`
 * every [intervalMs] for as long as the composable is in the
 * composition. Lets a card display an age-since-event readout
 * ("Last handshake 12s ago") that ticks every second on its own,
 * independent of whether the underlying data flow happens to be
 * pushing fresh values that recomposition can latch onto.
 *
 * Without this the "Last handshake Ns ago" line on the tunnel detail
 * screen sat frozen between WG handshakes (every ~2 minutes) — the
 * recomposition only fired when [ThroughputStats] emitted a
 * structurally-different value, which doesn't happen on a quiet
 * tunnel where rxBytes/txBytes round to the same KB bucket.
 */
@Composable
fun rememberCurrentTimeMs(intervalMs: Long = 1_000L): State<Long> {
    val state = remember { mutableLongStateOf(System.currentTimeMillis()) }
    LaunchedEffect(intervalMs) {
        while (true) {
            state.longValue = System.currentTimeMillis()
            delay(intervalMs)
        }
    }
    return state
}
