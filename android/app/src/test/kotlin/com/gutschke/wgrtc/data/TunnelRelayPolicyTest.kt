package com.gutschke.wgrtc.data

import kotlinx.serialization.json.Json
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

/**
 * Schema + migration tests for the v2 §11.3 additions to [Tunnel]:
 * `relayPolicy`, `intent`, `groupId`.  See `docs/ux-design-v2.md`
 * §12 for the migration plan.
 */
class TunnelRelayPolicyTest {

    private val json = Json {
        ignoreUnknownKeys = true
        encodeDefaults = true
    }

    @Test fun `freshly-constructed tunnel defaults to Ask + NoIntentYet + null groupId`() {
        val t = Tunnel(name = "alpha", configText = "[Interface]\n")
        assertEquals(RelayPolicy.Ask, t.relayPolicy)
        assertEquals(TunnelIntent.NoIntentYet, t.intent)
        assertEquals(null, t.groupId)
    }

    @Test fun `pre-v2 JSON without relayPolicy field deserialises to Ask`() {
        // What v0.2.x wrote: no relayPolicy, no intent, no groupId
        // fields at all.  encodeDefaults = true + nullable / enum
        // defaults absorb the missing values.
        val legacy = """
            {
              "id": "abc-123",
              "name": "alpha",
              "configText": "[Interface]\n",
              "source": "MANUAL",
              "brokerWss": null,
              "brokerKey": null,
              "saltB64": null,
              "hostMode": null
            }
        """.trimIndent()
        val t = json.decodeFromString(Tunnel.serializer(), legacy)
        assertEquals(RelayPolicy.Ask, t.relayPolicy)
        assertEquals(TunnelIntent.NoIntentYet, t.intent)
        assertEquals(null, t.groupId)
    }

    @Test fun `pre-v2 with cascade-on toggle still deserialises to Ask`() {
        // Critical migration property: the user who had the global
        // cascade toggle ON in v0.2.x must NOT auto-cascade in v2.
        // Their host tunnels start at Ask so the §2.3 banner fires
        // before any traffic flows.  See §12 final paragraph.
        //
        // SettingsStore.K_CASCADE_ENABLED is a SEPARATE blob from
        // tunnels.json — the per-tunnel defaults are unaffected
        // either way.  This test pins the property.
        val legacy = """{"id":"x","name":"y","configText":""}"""
        val t = json.decodeFromString(Tunnel.serializer(), legacy)
        assertEquals(RelayPolicy.Ask, t.relayPolicy)
    }

    @Test fun `roundtrip preserves new fields`() {
        val t = Tunnel(
            name = "alpha",
            configText = "[Interface]\n",
            relayPolicy = RelayPolicy.Always,
            intent = TunnelIntent.WantsOn,
            groupId = "00000000-0000-0000-0000-000000000001",
        )
        val text = json.encodeToString(Tunnel.serializer(), t)
        val back = json.decodeFromString(Tunnel.serializer(), text)
        assertEquals(RelayPolicy.Always, back.relayPolicy)
        assertEquals(TunnelIntent.WantsOn, back.intent)
        assertEquals("00000000-0000-0000-0000-000000000001", back.groupId)
    }

    @Test fun `RelayPolicy enum names are stable serialisation contracts`() {
        // Renaming any of these breaks user prefs on upgrade — the
        // serialised form is the enum's declared name.
        assertEquals("Ask", RelayPolicy.Ask.name)
        assertEquals("Always", RelayPolicy.Always.name)
        assertEquals("Never", RelayPolicy.Never.name)
        assertEquals(3, RelayPolicy.values().size)
    }
}
