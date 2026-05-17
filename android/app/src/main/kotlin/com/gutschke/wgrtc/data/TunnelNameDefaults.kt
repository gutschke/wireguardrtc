package com.gutschke.wgrtc.data

import java.util.Locale

/**
 * Pure helper that finds the smallest n such that
 * `"${prefix}${separator}${n}"` isn't already used as a tunnel
 * name in [existingNames].  Case-insensitive comparison, pinned
 * to [Locale.ROOT] so Turkish-locale handsets (`I` → `ı`) don't
 * miss collisions.
 *
 * Pulled out of [com.gutschke.wgrtc.WgrtcViewModel] so it can be
 * unit-tested without bootstrapping the full ViewModel.  See
 * `TunnelNameDefaultsTest`.
 */
fun nextAvailableTunnelName(
    existingNames: Collection<String>,
    prefix: String,
    separator: String = "-",
): String {
    val taken = existingNames.map { it.lowercase(Locale.ROOT) }.toSet()
    var n = 1
    while ("${prefix}${separator}${n}".lowercase(Locale.ROOT) in taken) n++
    return "${prefix}${separator}${n}"
}
