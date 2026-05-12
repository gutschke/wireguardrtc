package com.gutschke.wgrtc.data

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

/**
 * **Egress-policy decision logic.**
 *
 * The pure-function half of the egress selector — what *should*
 * happen given a policy and a snapshot of network availability.
 * The Android plumbing (looking up the actual `Network` handle,
 * binding sockets to it) lives in [EgressSelector]; this test
 * deliberately covers only the decision matrix so it can run in
 * the plain JVM unit-test suite.
 *
 * The matrix is small enough to be exhaustive — 4 policies × 4
 * availability combinations = 16 cases.
 */
class EgressDecisionTest {

    @Test fun osDefaultPolicyAlwaysReturnsOsDefault() {
        for (wifi in listOf(false, true)) {
            for (cell in listOf(false, true)) {
                assertEquals(EgressDecision.OS_DEFAULT,
                    decideEgress(EgressPolicy.OsDefault, wifi, cell),
                    "OsDefault must ignore network availability " +
                        "(wifi=$wifi, cell=$cell)")
            }
        }
    }

    @Test fun wifiOnlyRequiresWifiPresent() {
        assertEquals(EgressDecision.FAIL_WIFI_REQUIRED,
            decideEgress(EgressPolicy.WifiOnly, wifiAvailable = false, cellularAvailable = false))
        assertEquals(EgressDecision.FAIL_WIFI_REQUIRED,
            decideEgress(EgressPolicy.WifiOnly, wifiAvailable = false, cellularAvailable = true),
            "WifiOnly must NOT fall back to cellular")
        assertEquals(EgressDecision.USE_WIFI,
            decideEgress(EgressPolicy.WifiOnly, wifiAvailable = true, cellularAvailable = false))
        assertEquals(EgressDecision.USE_WIFI,
            decideEgress(EgressPolicy.WifiOnly, wifiAvailable = true, cellularAvailable = true))
    }

    @Test fun wifiPreferredFallsBackToOsDefault() {
        assertEquals(EgressDecision.OS_DEFAULT,
            decideEgress(EgressPolicy.WifiPreferred, wifiAvailable = false, cellularAvailable = false),
            "no wifi → OS picks (will likely fail in practice, but " +
                "we surface that as a real connect-time error, not a policy refusal)")
        assertEquals(EgressDecision.OS_DEFAULT,
            decideEgress(EgressPolicy.WifiPreferred, wifiAvailable = false, cellularAvailable = true),
            "no wifi but cell present → OS picks (likely cellular)")
        assertEquals(EgressDecision.USE_WIFI,
            decideEgress(EgressPolicy.WifiPreferred, wifiAvailable = true, cellularAvailable = false))
        assertEquals(EgressDecision.USE_WIFI,
            decideEgress(EgressPolicy.WifiPreferred, wifiAvailable = true, cellularAvailable = true))
    }

    @Test fun cellularOnlyRequiresCellularPresent() {
        assertEquals(EgressDecision.FAIL_CELLULAR_REQUIRED,
            decideEgress(EgressPolicy.CellularOnly, wifiAvailable = false, cellularAvailable = false))
        assertEquals(EgressDecision.FAIL_CELLULAR_REQUIRED,
            decideEgress(EgressPolicy.CellularOnly, wifiAvailable = true, cellularAvailable = false),
            "CellularOnly must NOT fall back to wifi")
        assertEquals(EgressDecision.USE_CELLULAR,
            decideEgress(EgressPolicy.CellularOnly, wifiAvailable = false, cellularAvailable = true))
        assertEquals(EgressDecision.USE_CELLULAR,
            decideEgress(EgressPolicy.CellularOnly, wifiAvailable = true, cellularAvailable = true))
    }

    @Test fun serializeRoundTripsAllPolicies() {
        for (p in listOf(
            EgressPolicy.OsDefault,
            EgressPolicy.WifiOnly,
            EgressPolicy.WifiPreferred,
            EgressPolicy.CellularOnly,
        )) {
            val s = p.serialize()
            assertEquals(p, parseEgressPolicy(s),
                "policy must survive a serialize/parse round trip ($p → $s → ?)")
        }
    }

    @Test fun parseUnknownStringFallsBackToOsDefault() {
        // Forwards-compat: if a future build writes "named:foo"
        // and the user downgrades, we must not crash.
        assertEquals(EgressPolicy.OsDefault, parseEgressPolicy(null),
            "null pref (never written) → OsDefault")
        assertEquals(EgressPolicy.OsDefault, parseEgressPolicy(""),
            "empty pref → OsDefault")
        assertEquals(EgressPolicy.OsDefault, parseEgressPolicy("named:cascade"),
            "unknown variant → OsDefault (forwards compat)")
        assertEquals(EgressPolicy.OsDefault, parseEgressPolicy("gibberish"))
    }
}
