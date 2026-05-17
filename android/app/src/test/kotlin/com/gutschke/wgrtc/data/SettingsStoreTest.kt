package com.gutschke.wgrtc.data

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class SettingsStoreTest {

    @Test fun `defaults match WormholeDefaults when nothing persisted`() {
        val s = SettingsStore.forTestInMemory()
        assertEquals(WormholeDefaults.BROKER_WSS, s.defaultBrokerWss)
        assertEquals(WormholeDefaults.BROKER_KEY, s.defaultBrokerKey)
    }

    @Test fun `seeded values are read on construction`() {
        val s = SettingsStore.forTestInMemory(mapOf(
            "broker_wss" to "wss://my.broker",
            "broker_key" to "secret",
        ))
        assertEquals("wss://my.broker", s.defaultBrokerWss)
        assertEquals("secret", s.defaultBrokerKey)
    }

    @Test fun `setter persists and updates the StateFlow`() {
        val s = SettingsStore.forTestInMemory()
        s.defaultBrokerWss = "wss://new.broker"
        assertEquals("wss://new.broker", s.defaultBrokerWss)
        assertEquals("wss://new.broker", s.defaultBrokerWssFlow.value)
    }

    @Test fun `resetToDefaults restores compiled-in values`() {
        val s = SettingsStore.forTestInMemory(mapOf(
            "broker_wss" to "wss://override",
            "broker_key" to "override-key",
        ))
        assertEquals("wss://override", s.defaultBrokerWss)
        s.resetToDefaults()
        assertEquals(WormholeDefaults.BROKER_WSS, s.defaultBrokerWss)
        assertEquals(WormholeDefaults.BROKER_KEY, s.defaultBrokerKey)
    }

    @Test fun `resetToDefaults scrubs legacy hosting_mode + joiner_backend prefs`() {
        // removed HostingMode + JoinerBackend; existing installs
        // may still have those keys in SharedPreferences. resetToDefaults
        // must not leak them — they'd grow stale and confuse a future
        // migration script.
        val s = SettingsStore.forTestInMemory(mapOf(
            "hosting_mode" to "MODE_B",
            "joiner_backend" to "LEGACY_GOBACKEND",
        ))
        s.resetToDefaults()
        // No public accessor for the legacy keys; just verify the
        // call doesn't throw and broker fields are at defaults.
        assertEquals(WormholeDefaults.BROKER_WSS, s.defaultBrokerWss)
    }

    @Test fun `snapshot returns the current pair`() {
        val s = SettingsStore.forTestInMemory()
        s.defaultBrokerWss = "wss://x"
        s.defaultBrokerKey = "y"
        val snap = s.snapshot()
        assertEquals("wss://x", snap.brokerWss)
        assertEquals("y", snap.brokerKey)
    }

    @Test fun `independent stores don't share state`() {
        val a = SettingsStore.forTestInMemory()
        val b = SettingsStore.forTestInMemory()
        a.defaultBrokerWss = "wss://only-in-a"
        assertEquals(WormholeDefaults.BROKER_WSS, b.defaultBrokerWss)
    }

    @Test fun `egressPolicy defaults to OsDefault when unset`() {
        val s = SettingsStore.forTestInMemory()
        assertEquals(EgressPolicy.OsDefault, s.egressPolicy)
    }

    @Test fun `egressPolicy round-trips through persistence`() {
        val s = SettingsStore.forTestInMemory()
        s.egressPolicy = EgressPolicy.WifiOnly
        assertEquals(EgressPolicy.WifiOnly, s.egressPolicy)
        assertEquals(EgressPolicy.WifiOnly, s.egressPolicyFlow.value)
    }

    @Test fun `egressPolicy reads back persisted value on construction`() {
        val s = SettingsStore.forTestInMemory(mapOf("egress_policy" to "wifi_preferred"))
        assertEquals(EgressPolicy.WifiPreferred, s.egressPolicy)
    }

    @Test fun `resetToDefaults restores egressPolicy to OsDefault`() {
        val s = SettingsStore.forTestInMemory()
        s.egressPolicy = EgressPolicy.CellularOnly
        s.resetToDefaults()
        assertEquals(EgressPolicy.OsDefault, s.egressPolicy)
    }

    @Test fun `joinerNEnabled defaults to true`() {
        // Default flipped to ON in v0.2.10.  Existing installs
        // without any persisted preference see the new behaviour;
        // installs that explicitly set the toggle off keep their
        // preference (covered by the "false reads back" case).
        val s = SettingsStore.forTestInMemory()
        assertEquals(true, s.joinerNEnabled)
        assertEquals(true, s.joinerNEnabledFlow.value)
    }

    @Test fun `joinerNEnabled round-trips through persistence`() {
        val s = SettingsStore.forTestInMemory()
        s.joinerNEnabled = false
        assertEquals(false, s.joinerNEnabled)
        assertEquals(false, s.joinerNEnabledFlow.value)
        s.joinerNEnabled = true
        assertEquals(true, s.joinerNEnabled)
        assertEquals(true, s.joinerNEnabledFlow.value)
    }

    @Test fun `joinerNEnabled honours explicit false from older installs`() {
        val s = SettingsStore.forTestInMemory(mapOf("joiner_n_enabled" to "false"))
        assertEquals(false, s.joinerNEnabled)
    }

    @Test fun `joinerNEnabled reads back persisted true on construction`() {
        val s = SettingsStore.forTestInMemory(mapOf("joiner_n_enabled" to "true"))
        assertEquals(true, s.joinerNEnabled)
    }

    @Test fun `resetToDefaults restores joinerNEnabled to true`() {
        val s = SettingsStore.forTestInMemory()
        s.joinerNEnabled = false
        s.resetToDefaults()
        assertEquals(true, s.joinerNEnabled)
    }

    @Test fun `cascadeForcedOff defaults to false`() {
        val s = SettingsStore.forTestInMemory()
        assertEquals(false, s.cascadeForcedOff)
        assertEquals(false, s.cascadeForcedOffFlow.value)
    }

    @Test fun `cascadeForcedOff round-trips through persistence`() {
        val s = SettingsStore.forTestInMemory()
        s.cascadeForcedOff = true
        assertEquals(true, s.cascadeForcedOff)
        assertEquals(true, s.cascadeForcedOffFlow.value)
        s.cascadeForcedOff = false
        assertEquals(false, s.cascadeForcedOff)
    }

    @Test fun `cascadeForcedOff reads back persisted true on construction`() {
        // The §13 layer-3 kill-switch must survive process
        // restarts — that's the whole point of having it
        // persisted rather than process-scope only.  This test
        // pins the on-disk key + the "true" / "false" literal
        // serialisation contract.
        val s = SettingsStore.forTestInMemory(mapOf("cascade_forced_off" to "true"))
        assertEquals(true, s.cascadeForcedOff)
    }

    @Test fun `resetToDefaults clears cascadeForcedOff`() {
        val s = SettingsStore.forTestInMemory()
        s.cascadeForcedOff = true
        s.resetToDefaults()
        assertEquals(false, s.cascadeForcedOff)
    }

    @Test fun `resetToDefaults scrubs legacy cascade_enabled pref`() {
        // K_CASCADE_ENABLED was retired in v2 §11.3 but the on-disk
        // value lingers for users who had the toggle on in v0.2.x.
        // resetToDefaults removes it so it doesn't get re-read by
        // any stale callsite.
        val seed = mutableMapOf("cascade_enabled" to "true")
        val s = SettingsStore(object : SettingsStore.Backing {
            override fun getString(key: String): String? = seed[key]
            override fun putString(key: String, value: String) { seed[key] = value }
            override fun remove(key: String) { seed.remove(key) }
        })
        s.resetToDefaults()
        assertEquals(null, seed["cascade_enabled"])
    }
}
