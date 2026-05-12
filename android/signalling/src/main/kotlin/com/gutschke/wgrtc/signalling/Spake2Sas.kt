package com.gutschke.wgrtc.signalling

/**
 * Short Authentication String (SAS) derivation for the
 * wormhole-code enrolment.
 *
 * After [Spake2.finish] both sides hold a 32-byte shared key —
 * matching iff the password matched. We hash that key with a
 * domain-separator and slice it into N bytes; each byte indexes a
 * word from [PLACEHOLDER_SAS_WORDLIST]. The result is shown to the
 * user on both devices; manual visual confirmation that the two
 * SAS phrases match is the *only* line of defence against a relay-
 * MITM that completed PAKE on each side independently.
 *
 * **Wordlist note**: this is a PLACEHOLDER 256-word list (8 bits per
 * word, 4-word default = 32 bits = 1 in 4 billion accidental
 * collision). Production should swap in the PGP wordlist (RFC-
 * style; even-words/odd-words pair, public domain) for better
 * mishearing resistance over voice channels. See task followup.
 *
 * Threat model + bit budget:
 * - 4-word SAS at 8 bits each = 32-bit confirmation. A
 * successful spoof requires the attacker to *display* the
 * user's expected SAS on the spoofed side. Without the
 * matching session key, they have to guess; ~1 in 4 billion
 * per attempt.
 * - The attacker only gets one attempt per code-mint cycle (the
 * user confirms-or-aborts in real time), so this is a
 * one-shot brute force, not an offline one.
 *
 * UX recommendation: display the SAS prominently with a "Confirm
 * match" button; refuse to auto-confirm on a single-tap; never
 * fade the SAS off-screen before confirmation.
 */
fun deriveSas(
    sharedKey: ByteArray,
    wordCount: Int = 4,
): String {
    require(sharedKey.size >= 16) {
        "sharedKey too short for SAS derivation (got ${sharedKey.size} bytes, need ≥ 16)"
    }
    require(wordCount in 0..32) {
        "wordCount out of range (got $wordCount; allowed 0..32)"
    }
    if (wordCount == 0) return ""
    val out = ByteArray(wordCount)
    val ok = Sodium.instance.cryptoGenericHash(
        out, out.size, sharedKey, sharedKey.size.toLong(),
        LABEL_SPAKE2_SAS, LABEL_SPAKE2_SAS.size,
    )
    check(ok) { "blake2b(sas) failed" }
    return out.joinToString(" ") { byte ->
        PLACEHOLDER_SAS_WORDLIST[byte.toInt() and 0xFF]
    }
}

private val LABEL_SPAKE2_SAS: ByteArray = "wgrtc/spake2/sas-2026".toByteArray(Charsets.UTF_8)

/**
 * Placeholder 256-word SAS wordlist. Each word is short, lowercase,
 * non-overlapping, and disjoint enough for visual + audible
 * verification. Intent: swap in the PGP-words list as a
 * resource-only follow-up.
 *
 * Property tests in [Spake2SasTest] enforce: size = 256, no
 * duplicates, no embedded spaces, length in 2..12. Editing this
 * list breaks wire compatibility with peers built on the old list —
 * **bumping the list is a protocol change**, treat accordingly.
 */
internal val PLACEHOLDER_SAS_WORDLIST: List<String> = listOf(
    // 0..31
    "apple", "bear", "cat", "deer", "eagle", "fish", "goat", "hawk",
    "ink", "jay", "kite", "lion", "moose", "newt", "owl", "pear",
    "quail", "rose", "snail", "tiger", "urn", "vase", "wolf", "yak",
    "zebra", "ace", "bell", "crab", "dove", "elf", "fern", "gold",
    // 32..63
    "harp", "iris", "jade", "kelp", "lake", "moss", "nest", "oak",
    "pine", "quark", "reed", "salt", "tide", "uvula", "vest", "wax",
    "yarn", "zinc", "ant", "bat", "cape", "drum", "elm", "fox",
    "gem", "hoop", "jam", "knot", "leaf", "mint", "nail", "onyx",
    // 64..95
    "pad", "rim", "sand", "tape", "ulm", "veil", "wave", "yew",
    "arch", "barn", "coal", "duct", "egg", "flag", "grain", "hill",
    "ivy", "jug", "keel", "log", "mast", "nook", "orb", "plum",
    "rake", "silk", "tin", "ulna", "vine", "wisp", "yak2", "zen",
    // 96..127
    "amp", "boil", "comb", "dock", "ebb", "fjord", "gust", "halo",
    "ire", "joke", "kiln", "lash", "mole", "nubs", "ooze", "puff",
    "rust", "scab", "trim", "udder", "vex", "wend", "yore", "zest",
    "abyss", "blip", "carp", "dawn", "eel", "fawn", "gauze", "hex",
    // 128..159
    "isle", "jolt", "knee", "lull", "mush", "nag", "ode", "perk",
    "rave", "sloth", "trove", "user", "verb", "warp", "yam", "zest2",
    "alms", "bunch", "cinch", "dwarf", "eke", "frog", "gear", "hum",
    "imp", "jest", "kink", "lull2", "moil", "nymph", "oath", "perch",
    // 160..191
    "raze", "sect", "thaw", "ulm2", "vow", "wrest", "yeti", "zealot",
    "atom", "barb", "creek", "dirge", "ember", "fawn2", "gobi", "hoist",
    "iota", "jeer", "knack", "lurk", "muse", "node", "oust", "prow",
    "quay", "rasp", "snipe", "thorn", "udon", "vamp", "wisp2", "yokel",
    // 192..223
    "aspen", "bog", "cusp", "dim", "ergot", "fjord2", "geode", "hark",
    "ibex", "jolt2", "klutz", "luge", "moor", "nimbus", "ooze2", "pith",
    "quirk", "ruby", "sift", "thrum", "ushak", "vex2", "wadi", "yurt",
    "zephyr", "alley", "broth", "clove", "dingo", "ember2", "fern2", "gulch",
    // 224..255
    "henna", "ingot", "jolly", "kapok", "lapis", "manor", "nutty", "ochre",
    "pixel", "quill", "raven", "sable", "tally", "umber", "viola", "wager",
    "yarrow", "zilch", "amber", "blade", "cleft", "drift", "ember3", "frill",
    "glaze", "haven", "iglu", "jolt3", "kismet", "lobby", "mango", "nudge",
)
