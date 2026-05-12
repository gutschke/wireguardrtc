package com.gutschke.wgrtc.data

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.DynamicTest
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestFactory
import java.io.File
import java.io.InputStream
import java.util.Base64

/**
 * regression: HOST_MODE tunnels' [Tunnel.configText] holds only
 * the `[Interface]` block; the `[Peer]` blocks are stitched in by
 * [renderWgConfig] (and surfaced as bytes by [kernelConfigStream]).
 *
 * Two layers of protection:
 *
 * 1. **Behavioural:** every backend-bound `wg-quick` rendering for
 * a HOST_MODE tunnel with enrolled peers MUST contain a
 * `PublicKey = ...` line for each enrolled peer.
 * 2. **Lint:** every Kotlin source file under `app/src/main/`
 * that converts a [Tunnel.configText] to bytes
 * (`.configText.byteInputStream()`) must be on an explicit
 * allowlist, with the rationale spelled out in this test —
 * forcing future changes to confront the trade-off
 * instead of silently re-introducing it.
 */
class RenderWgConfigContractTest {

    private val privB64 = Base64.getEncoder().encodeToString(ByteArray(32) { 1.toByte() })
    private val peerB64 = Base64.getEncoder().encodeToString(ByteArray(32) { 2.toByte() })

    @Test
    fun `renderWgConfig for HOST_MODE-with-peers includes the peer pubkey`() {
        val t = hostTunnel(peers = listOf(EnrolledPeer(peerB64, "10.99.0.2", "g", 1L)))
        val rendered = renderWgConfig(t)
        assertTrue(rendered.contains("PublicKey = $peerB64"),
            "rendered config should include the enrolled peer's pubkey:\n$rendered")
        assertTrue(rendered.contains("AllowedIPs = 10.99.0.2/32"))
    }

    @Test
    fun `renderWgConfig for HOST_MODE-without-peers equals configText`() {
        val t = hostTunnel(peers = emptyList())
        assertEquals(t.configText, renderWgConfig(t))
    }

    @Test
    fun `renderWgConfig for non-HOST_MODE returns configText untouched`() {
        val cfg = "[Interface]\nPrivateKey = $privB64\nAddress = 10.0.0.2/32\n"
        val t = Tunnel(
            id = "client-1",
            name = "client",
            configText = cfg,
            source = Tunnel.Source.LEGACY,
        )
        assertEquals(cfg, renderWgConfig(t))
    }

    @Test
    fun `kernelConfigStream is a byte view of renderWgConfig`() {
        val t = hostTunnel(peers = listOf(EnrolledPeer(peerB64, "10.99.0.2", "g", 1L)))
        val expected = renderWgConfig(t).toByteArray(Charsets.UTF_8)
        val actual = t.kernelConfigStream().use(InputStream::readBytes)
        assertTrue(expected.contentEquals(actual),
            "kernelConfigStream output should match renderWgConfig bytes verbatim")
    }

    @Test
    fun `kernelConfigStream for HOST_MODE with two peers includes both`() {
        val pk2 = Base64.getEncoder().encodeToString(ByteArray(32) { 3.toByte() })
        val t = hostTunnel(peers = listOf(
            EnrolledPeer(peerB64, "10.99.0.2", "g1", 1L),
            EnrolledPeer(pk2, "10.99.0.3", "g2", 2L),
        ))
        val rendered = t.kernelConfigStream().use { String(it.readBytes()) }
        assertTrue(rendered.contains(peerB64), "first peer missing")
        assertTrue(rendered.contains(pk2), "second peer missing")
    }

    /**
     * Source-level lint: every reference to `.configText.byteInputStream()`
     * in `app/src/main/kotlin/` must appear at a known-safe location,
     * tagged here with a reason so future contributors confront .
     *
     * Adding a new occurrence is a deliberate act: either it's
     * validation-only (parse + discard for input checking), or the
     * surrounding code has already short-circuited HOST_MODE before
     * reaching the call. Otherwise use [Tunnel.kernelConfigStream]
     * which goes through [renderWgConfig].
     */
    @TestFactory
    fun `every direct configText byteInputStream callsite is on the allowlist`(): List<DynamicTest> {
        val mainSourceRoot = locateSourceRoot()
        val pattern = Regex("""\.configText\.byteInputStream\(\)""")
        // Each entry: (file path under app/src/main/kotlin/, line-substring fingerprint, why this is safe).
        val allowlist = mapOf<String, List<Pair<String, String>>>(
            // All direct configText.byteInputStream() callsites were
            // wireguard-android-era; deleted in . The allowlist
            // is kept as a guard rail so a future regression at a
            // new callsite still fails this test.
        )

        val findings = mutableListOf<Triple<String, Int, String>>()
        mainSourceRoot.walkTopDown()
            .filter { it.isFile && it.name.endsWith(".kt") }
            .forEach { file ->
                file.readLines().forEachIndexed { idx, line ->
                    val trimmed = line.trim()
                    // Skip kdoc / single-line comments — they often
                    // *describe* the dangerous pattern. Code inside
                    // a `/* ... */` block can't be reliably stripped
                    // without a real parser; we accept the false-
                    // positive risk and rely on the small footprint
                    // of `Tunnel.kt`'s kdoc as the only block-comment
                    // mention right now.
                    if (trimmed.startsWith("//") ||
                        trimmed.startsWith("*") ||
                        trimmed.startsWith("/*")) return@forEachIndexed
                    if (pattern.containsMatchIn(line)) {
                        val rel = file.relativeTo(mainSourceRoot).invariantSeparatorsPath
                        findings += Triple(rel, idx + 1, trimmed)
                    }
                }
            }

        return findings.map { (relPath, lineNo, line) ->
            DynamicTest.dynamicTest("$relPath:$lineNo — $line") {
                val allowed = allowlist[relPath].orEmpty()
                val matched = allowed.any { (fingerprint, _) -> line.contains(fingerprint) }
                assertTrue(matched,
                    "-class regression risk at $relPath:$lineNo\n" +
                        " $line\n\n" +
                        "Direct `.configText.byteInputStream()` is dangerous for HOST_MODE tunnels — " +
                        "the [Interface] block doesn't include enrolled peers. Either:\n" +
                        " (a) replace with `t.kernelConfigStream()` (goes through renderWgConfig); or\n" +
                        " (b) add this fingerprint + a justification to the allowlist in " +
                        "RenderWgConfigContractTest.kt with a brief explanation of why HOST_MODE peer " +
                        "loss is impossible at this site.")
            }
        }
    }

    /** Search up from the working directory for the `app/src/main/kotlin`
     * source tree. Tests run from `app/` (gradle) or the project root
     * depending on harness — we accept either. */
    private fun locateSourceRoot(): File {
        val candidates = listOf(
            File("src/main/kotlin"),
            File("app/src/main/kotlin"),
            File("../app/src/main/kotlin"),
        )
        return candidates.firstOrNull { it.isDirectory }
            ?: error("can't find app/src/main/kotlin from ${File(".").absolutePath}")
    }

    private fun hostTunnel(peers: List<EnrolledPeer>): Tunnel = Tunnel(
        id = "host-1",
        name = "host",
        configText = """
            [Interface]
            PrivateKey = $privB64
            Address = 10.99.0.1/24
            ListenPort = 51820
        """.trimIndent(),
        source = Tunnel.Source.HOST_MODE,
        hostMode = HostModeConfig(
            subnet = "10.99.0.0/24",
            enrolledPeers = peers,
        ),
    )
}
