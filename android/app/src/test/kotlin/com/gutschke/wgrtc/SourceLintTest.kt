package com.gutschke.wgrtc

import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.File

/**
 * Pure-JVM source lints that pin invariants we don't want to lose to a
 * silent refactor.  Each test reads a single file from the project tree
 * and asserts on its content.  They are deliberately fragile — if a
 * fix lands, update the test together with the code.
 *
 * Why source lints and not behavioral tests:
 *   - The properties we're protecting are *configuration* choices
 *     (manifest flags, which constructor is called) rather than
 *     functions we can call and assert against.
 *   - The bugs they pin were silent regressions discovered only by
 *     real-device testing.  Cheap source lints close the loop
 *     without requiring an instrumented test rig for every property.
 */
class SourceLintTest {

    private val projectRoot: File = File("..").canonicalFile

    private fun read(relPath: String): String {
        val f = File(projectRoot, relPath)
        check(f.exists()) { "missing project file: $f" }
        return f.readText()
    }

    /** Strip everything from a `<!-- ... -->` comment open to its
     *  close (handles multi-line block comments).  Crude — doesn't
     *  handle nested or unbalanced — but adequate for the
     *  AndroidManifest.xml we ship. */
    private fun stripXmlComments(xml: String): String {
        val sb = StringBuilder(xml.length)
        var i = 0
        while (i < xml.length) {
            val open = xml.indexOf("<!--", i)
            if (open < 0) { sb.append(xml, i, xml.length); break }
            sb.append(xml, i, open)
            val close = xml.indexOf("-->", open + 4)
            if (close < 0) break
            i = close + 3
        }
        return sb.toString()
    }

    /** Strip `//`-style line comments from a Kotlin file.  Doesn't
     *  respect strings, but adequate for matching well-known
     *  identifiers. */
    private fun stripKotlinLineComments(src: String): String =
        src.lineSequence().joinToString("\n") { line ->
            val i = line.indexOf("//")
            if (i < 0) line else line.substring(0, i)
        }

    // ----- AndroidManifest: Auto Backup is disabled --------------------

    /**
     * v0.2.12 disabled Android Auto Backup so the app's
     * `tunnels.json` (which holds WireGuard PrivateKey material)
     * stops being uploaded to Google Drive on the default backup
     * transport.  If any future refactor flips `allowBackup` back
     * to true (or just drops the attribute, which defaults to
     * true), this test fails.
     */
    @Test fun `AndroidManifest declares allowBackup false`() {
        val xml = stripXmlComments(read("app/src/main/AndroidManifest.xml"))
        assertTrue(
            xml.contains("""android:allowBackup="false""""),
            "AndroidManifest.xml must declare android:allowBackup=\"false\". " +
                "Without it Android defaults to true, and tunnels.json " +
                "(including WG PrivateKeys) gets auto-backed-up to Google " +
                "Drive.  See v0.2.12 commit on backup-disable.",
        )
        assertFalse(
            Regex("""android:allowBackup="true"""").containsMatchIn(xml),
            "AndroidManifest.xml must NOT declare android:allowBackup=\"true\".",
        )
    }

    @Test fun `AndroidManifest references dataExtractionRules and fullBackupContent`() {
        val xml = stripXmlComments(read("app/src/main/AndroidManifest.xml"))
        assertTrue(
            xml.contains("android:dataExtractionRules="),
            "Manifest should reference android:dataExtractionRules so " +
                "Android 12+ also gets a structured no-backup rule.",
        )
        assertTrue(
            xml.contains("android:fullBackupContent="),
            "Manifest should reference android:fullBackupContent so legacy " +
                "backup transports also see the exclusion rules.",
        )
    }

    @Test fun `data_extraction_rules excludes every domain on cloud-backup and device-transfer`() {
        val xml = read("app/src/main/res/xml/data_extraction_rules.xml")
        // Both transports must include exclude rules for the major
        // app-data domains.  We don't require any specific exact
        // string — just that every domain shows up at least once.
        for (domain in listOf("root", "file", "database", "sharedpref", "external")) {
            assertTrue(
                Regex("""<exclude\s+domain="$domain"\s*/>""").containsMatchIn(xml),
                "data_extraction_rules.xml must exclude domain=\"$domain\".",
            )
        }
        assertTrue(xml.contains("<cloud-backup>"), "must contain <cloud-backup> block")
        assertTrue(xml.contains("<device-transfer>"), "must contain <device-transfer> block")
    }

    // ----- WgrtcViewModel: joiner-N is wired into the throughput sampler

    /**
     * v0.2.12 fixed the throughput sampler that quietly skipped
     * joiner-N tunnels (it iterated only the legacy single-joiner
     * state).  This source lint asserts the sampler reads the
     * joiner-N state holder alongside the legacy one, so a future
     * refactor doesn't accidentally drop the joiner-N branch.
     */
    @Test fun `throughput sampler reads joiner-N state`() {
        val src = stripKotlinLineComments(
            read("app/src/main/kotlin/com/gutschke/wgrtc/WgrtcViewModel.kt"))
        // sampleOnce is the lone caller — assert it touches both
        // state holders.  We pin the symbol names rather than the
        // surrounding control flow so harmless reformatting stays
        // green.
        assertTrue(
            src.contains("_activeJoinerNTunnelIds.value") &&
                src.contains("activeJoinerNBinding"),
            "WgrtcViewModel must read both _activeJoinerNTunnelIds and " +
                "activeJoinerNBinding from the throughput sampler.  Without " +
                "those, joiner-N tunnels never get sampled and the UI shows " +
                "zero bytes forever.  See v0.2.12 commit on joiner-N stats.",
        )
        // Negative pin: the legacy state alone is not enough.
        assertTrue(
            src.contains("snapshotStats(") &&
                src.contains("joinerNBinding"),
            "Throughput sampler must call snapshotStats() on the " +
                "joiner-N binding for each active joiner-N tunnel id.",
        )
    }

    // ----- JoinerNVpnService exposes snapshotStats(tunnelId) -----------

    @Test fun `addLegacyTunnel does not silently consume the Bridge flow`() {
        // §11.6 ambient-context-bug fix: round-2 critic on commit
        // f21ba653 caught that addLegacyTunnel reading
        // peekBridgeGroupIdForNewTunnel would stamp ANY paste / QR /
        // wormhole import while a Bridge wizard happened to be open.
        // The explicit-API split (addLegacyTunnelInBridgeFlow) is the
        // fix; pin it so a future "convenience refactor" can't
        // re-introduce the ambient call.
        val src = stripKotlinLineComments(
            read("app/src/main/kotlin/com/gutschke/wgrtc/WgrtcViewModel.kt"))
        // Locate the body of addLegacyTunnel (the non-bridge entry
        // point) and assert it doesn't peek the Bridge state.
        // Method-body slicing on Kotlin source via regex is brittle
        // in general but this entry point's signature is stable.
        val legacyBody = Regex(
            """fun\s+addLegacyTunnel\s*\([^)]*\)\s*:\s*Tunnel\s*\{[\s\S]*?\n\s{1}\}""",
        ).find(src)?.value
        assertTrue(legacyBody != null,
            "couldn't locate addLegacyTunnel body — did the signature change?")
        assertTrue(
            !legacyBody!!.contains("peekBridgeGroupIdForNewTunnel"),
            "addLegacyTunnel must NOT read the Bridge flow state. " +
                "Tile-#3 wizard should call addLegacyTunnelInBridgeFlow " +
                "explicitly; ambient-state-read in the shared entry " +
                "point is the f21ba653-round-2 bug. " +
                "See docs/ux-design-v2.md §11.6.",
        )
        // Positive pin: the explicit wizard entry point exists AND
        // reads the bridge state.
        assertTrue(
            src.contains("fun addLegacyTunnelInBridgeFlow") &&
                src.contains("peekBridgeGroupIdForNewTunnel"),
            "addLegacyTunnelInBridgeFlow must exist and read the " +
                "Bridge flow state.",
        )
    }

    @Test fun `addHostModeTunnel does not silently consume the Bridge flow`() {
        // Symmetric pin to the joiner-side test.  The host-mode
        // create path has its own non-Bridge call sites (Tile-#2,
        // imports, replays) and would re-introduce the
        // ambient-context bug if peekBridgeGroupIdForNewTunnel
        // leaked back into the shared entry point.
        val src = stripKotlinLineComments(
            read("app/src/main/kotlin/com/gutschke/wgrtc/WgrtcViewModel.kt"))
        val hostBody = Regex(
            """fun\s+addHostModeTunnel\s*\([\s\S]*?\)\s*:\s*Tunnel\s*\{[\s\S]*?\n\s{1}\}""",
        ).find(src)?.value
        assertTrue(hostBody != null,
            "couldn't locate addHostModeTunnel body — did the signature change?")
        assertTrue(
            !hostBody!!.contains("peekBridgeGroupIdForNewTunnel"),
            "addHostModeTunnel must NOT read the Bridge flow state. " +
                "Tile-#3 wizard should call addHostModeTunnelInBridgeFlow " +
                "explicitly; ambient-state-read in the shared entry " +
                "point is the f21ba653-round-2 bug, symmetric to " +
                "addLegacyTunnel.",
        )
        assertTrue(
            src.contains("fun addHostModeTunnelInBridgeFlow") &&
                src.split("addHostModeTunnelInBridgeFlow")[1]
                    .contains("peekBridgeGroupIdForNewTunnel"),
            "addHostModeTunnelInBridgeFlow must exist and read the " +
                "Bridge flow state.",
        )
    }

    @Test fun `JoinerNVpnService exposes snapshotStats(tunnelId)`() {
        val src = stripKotlinLineComments(
            read("app/src/main/kotlin/com/gutschke/wgrtc/service/JoinerNVpnService.kt"))
        assertTrue(
            Regex("""fun\s+snapshotStats\s*\(\s*tunnelId\s*:\s*String\s*\)""")
                .containsMatchIn(src),
            "JoinerNVpnService must expose snapshotStats(tunnelId): UapiStats? " +
                "for the throughput sampler.  Without this the sampler can't " +
                "read per-tunnel stats for joiner-N tunnels.",
        )
    }
}
