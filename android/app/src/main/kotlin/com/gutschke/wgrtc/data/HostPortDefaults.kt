package com.gutschke.wgrtc.data

/**
 * §11.9 — find the next-free UDP listen port for a new host
 * tunnel.  Preserves the "51820 is the convention" expectation
 * when nothing else is bound there, then walks upward until the
 * first non-collision.
 *
 * Pure function so the UI can call it from a non-Composable
 * context and the test suite doesn't need to bootstrap a
 * ViewModel.  See `HostPortDefaultsTest`.
 *
 * @param existingPorts ports already bound by other host tunnels
 *   (from their persisted wg-quick `ListenPort` field).
 * @param preferred the first port to try.  Defaults to WireGuard's
 *   canonical 51820 — the same value [HostModeSetupScreen] used
 *   as a hardcoded placeholder pre-§11.9.
 * @return a port number in `[preferred, 65535]` that doesn't
 *   collide with [existingPorts].  Throws when no free port
 *   exists in the range, which shouldn't happen in practice
 *   (the user would need ~14k concurrent host tunnels).
 */
fun nextAvailableHostListenPort(
    existingPorts: Collection<Int>,
    preferred: Int = DEFAULT_HOST_LISTEN_PORT,
): Int {
    require(preferred in 1024..65535) {
        "preferred port must be in unprivileged range, got $preferred"
    }
    val taken = existingPorts.toSet()
    var p = preferred
    while (p in taken) {
        p++
        check(p <= 65535) {
            "no free UDP port available above $preferred (${existingPorts.size} already bound)"
        }
    }
    return p
}

/** WireGuard's canonical listen port.  See RFC + every wg-quick
 *  example.  We prefer this whenever it's free. */
const val DEFAULT_HOST_LISTEN_PORT = 51820

/**
 * Extract the `[Interface] ListenPort = N` value from a wg-quick
 * config block.  Returns null when the field is absent or
 * unparseable; callers fall back to whatever default they want
 * (usually [DEFAULT_HOST_LISTEN_PORT]).
 */
fun parseListenPortFromConfig(configText: String): Int? =
    parseInterfaceField(configText, "ListenPort")?.toIntOrNull()
