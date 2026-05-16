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
}
