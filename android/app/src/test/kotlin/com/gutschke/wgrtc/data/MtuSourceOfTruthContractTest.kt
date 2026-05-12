package com.gutschke.wgrtc.data

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.DynamicTest
import org.junit.jupiter.api.TestFactory
import java.io.File

/**
 * Pins the contract that **only [MtuMath]** carries the MTU
 * constants. Anyone introducing a hard-coded `1420` (or `1500`
 * or `1380` or…) into another file is forcing a future MTU
 * change to chase the number through the codebase — exactly the
 * kind of brittleness the user has been burned by on other
 * tunnel deployments.
 *
 * The allow-list below is the canonical place to acknowledge a
 * literal that *must* live outside [MtuMath] (e.g., test
 * fixtures that explicitly want a non-default value). A new
 * entry forces a code-review thought: "is this value
 * defensible without going through the MtuMath central
 * function?"
 */
class MtuSourceOfTruthContractTest {

    @TestFactory
    fun `no stray hard-coded 1420 outside MtuMath`(): List<DynamicTest> {
        val main = locateMainSourceRoot()
        // Files exempted from the "no bare 1420" rule + a one-line
        // justification per entry. Keep this list short.
        val exempt = mapOf(
            "com/gutschke/wgrtc/data/MtuMath.kt" to
                "the source of truth itself defines 1420 (DEFAULT_WG_MTU + the safeWgMtu test).",
            // (Other entries land here when justified.)
        )
        val findings = mutableListOf<Triple<String, Int, String>>()
        main.walkTopDown()
            .filter { it.isFile && it.name.endsWith(".kt") }
            .forEach { file ->
                val rel = file.relativeTo(main).path
                if (rel in exempt) return@forEach
                file.readLines().forEachIndexed { idx, line ->
                    // Skip kdoc / comment lines — they often
                    // *mention* the number to explain it.
                    val trimmed = line.trim()
                    if (trimmed.startsWith("//") || trimmed.startsWith("*")) return@forEachIndexed
                    // The whole-word boundary regex avoids false
                    // positives like 14200, 11420, 14201.
                    if (Regex("""\b1420\b""").containsMatchIn(trimmed)) {
                        findings += Triple(rel, idx + 1, trimmed)
                    }
                }
            }
        return findings.map { (path, line, snippet) ->
            DynamicTest.dynamicTest("$path:$line — `$snippet`") {
                throw AssertionError(
                    "Bare `1420` found at $path:$line. Replace with " +
                        "MtuMath.DEFAULT_WG_MTU, or add a justified exception " +
                        "to [MtuSourceOfTruthContractTest.exempt]."
                )
            }
        }.ifEmpty {
            listOf(DynamicTest.dynamicTest("no stray 1420s found") { /* pass */ })
        }
    }

    private fun locateMainSourceRoot(): File {
        // Tests run with the working directory at `app/` under
        // gradle. Walk up to find the project root and pin
        // app/src/main/kotlin.
        val cwd = File(System.getProperty("user.dir"))
        for (candidate in generateSequence(cwd) { it.parentFile }) {
            val main = File(candidate, "src/main/kotlin/com/gutschke/wgrtc")
            if (main.isDirectory) return File(candidate, "src/main/kotlin")
        }
        error("could not locate app/src/main/kotlin from $cwd")
    }
}
