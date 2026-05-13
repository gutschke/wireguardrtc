package com.gutschke.wgrtc.data

/**
 * **AllowedIPs canonicalization for ChromeOS compatibility.**
 *
 * `wg-quick`'s reference parser tolerates whitespace around commas
 * in `AllowedIPs = a/24, b/32` style values — the Linux `wg(8)`
 * source explicitly trims tokens before parsing them. But
 * **ChromeOS's WireGuard implementation does not**: any whitespace
 * inside the value causes the config to be rejected, with no
 * actionable error surfaced to the user. The user has to delete
 * the imported tunnel and re-import a space-free version.
 *
 * To stay portable, every wg-quick config blob we produce for an
 * *external* WG client (i.e. all SAS payloads, all manual-config
 * blobs, all enrollment renderings) must emit AllowedIPs without
 * any whitespace. Internal in-memory edits + persistence are
 * fine — the canonicalize happens at the producer side of every
 * wire output.
 *
 * Examples (input → output):
 * - `"10.0.0.0/24"` → `"10.0.0.0/24"`
 * - `"10.0.0.0/24, 192.168.1.0/24"` → `"10.0.0.0/24,192.168.1.0/24"`
 * - `"0.0.0.0/0, ::/0"` (double space) → `"0.0.0.0/0,::/0"`
 * - `" 10.0.0.0/24 , 192.168.1.0/24 "` (leading + trailing) → `"10.0.0.0/24,192.168.1.0/24"`
 * - `""` → `""` (empty stays empty — caller decides if that's an error)
 * - `",,"` (just separators) → `""` (empty entries dropped)
 *
 * Doesn't validate CIDR format — that's a different concern handled
 * by other parsers in the signalling layer (see [Cidr][com.gutschke.wgrtc.signalling.Cidr]).
 */
object WgAllowedIps {

    /**
     * Strip whitespace inside an AllowedIPs string + drop empty
     * entries. Stable + pure — same input always produces the
     * same output. Callers with a nullable should use
     * `value?.let { WgAllowedIps.canonicalize(it) }`.
     */
    fun canonicalize(raw: String): String =
        raw.splitToSequence(',')
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .joinToString(",")

    /** Compiled-in dual-stack full-tunnel default — already
     * canonicalized. Single source of truth so we don't have to
     * audit every literal `"0.0.0.0/0, ::/0"` we sprinkled
     * around the codebase before . */
    const val FULL_TUNNEL: String = "0.0.0.0/0,::/0"
}
