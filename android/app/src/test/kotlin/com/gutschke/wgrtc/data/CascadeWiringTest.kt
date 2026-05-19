package com.gutschke.wgrtc.data

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class CascadeWiringTest {

    /** Records every JNI call CascadeWiring would make so tests
     *  can assert on the exact call sequence without touching the
     *  .so. */
    private class RecordingBridge : CascadeWiring.Bridge {
        data class Call(val name: String, val args: List<Any?>)
        val calls = mutableListOf<Call>()

        override fun registerJoiner(stackHandle: Int, allowedIpsCsv: String?): Int {
            calls += Call("registerJoiner", listOf(stackHandle, allowedIpsCsv))
            return 0
        }
        override fun unregisterJoiner() {
            calls += Call("unregisterJoiner", emptyList())
        }
        override fun joinerAllowedIpsChanged(allowedIpsCsv: String?): Int {
            calls += Call("joinerAllowedIpsChanged", listOf(allowedIpsCsv))
            return 0
        }
        override fun joinerInterfaceAddrsChanged(addrsCsv: String?): Int {
            calls += Call("joinerInterfaceAddrsChanged", listOf(addrsCsv))
            return 0
        }
        override fun registerHostBridge(bridgeHandle: Int, peerSubnetsCsv: String?): Int {
            calls += Call("registerHostBridge", listOf(bridgeHandle, peerSubnetsCsv))
            return 0
        }
        override fun unregisterHostBridge(bridgeHandle: Int) {
            calls += Call("unregisterHostBridge", listOf(bridgeHandle))
        }
    }

    private inline fun withBridge(b: RecordingBridge, body: () -> Unit) {
        val restore = CascadeWiring.installBridgeForTest(b)
        try { body() } finally { restore.close() }
    }

    @Test fun `disabled by default — every on-method is a no-op`() {
        val b = RecordingBridge()
        withBridge(b) {
            CascadeWiring.onJoinerStackUp(42, "10.50.0.0/24")
            CascadeWiring.onJoinerAllowedIpsChanged("10.50.0.0/24")
            CascadeWiring.onHostBridgeUp(7, "10.99.0.0/24")
            CascadeWiring.onJoinerStackDown()
            CascadeWiring.onHostBridgeDown(7)
            assertTrue(b.calls.isEmpty(),
                "disabled CascadeWiring must not touch the bridge: ${b.calls}")
            assertFalse(CascadeWiring.isEnabled())
            val snap = CascadeWiring.snapshotState()
            assertNull(snap.joinerStackHandle)
            assertTrue(snap.hostBridges.isEmpty())
        }
    }

    @Test fun `enabled — joiner stack lifecycle round-trips`() {
        val b = RecordingBridge()
        withBridge(b) {
            CascadeWiring.setEnabled(true)
            CascadeWiring.onJoinerStackUp(42, "10.50.0.0/24,2001:db8::/64")
            CascadeWiring.onJoinerAllowedIpsChanged("10.50.0.0/24")
            CascadeWiring.onJoinerStackDown()

            val names = b.calls.map { it.name }
            assertEquals(
                listOf("registerJoiner", "joinerAllowedIpsChanged", "unregisterJoiner"),
                names,
            )
            assertEquals(
                listOf<Any?>(42, "10.50.0.0/24,2001:db8::/64"),
                b.calls[0].args,
            )
            assertEquals(
                listOf<Any?>("10.50.0.0/24"),
                b.calls[1].args,
            )
        }
    }

    @Test fun `enabled — host bridge lifecycle round-trips`() {
        val b = RecordingBridge()
        withBridge(b) {
            CascadeWiring.setEnabled(true)
            CascadeWiring.onHostBridgeUp(7, "10.99.0.0/24")
            CascadeWiring.onHostBridgeDown(7)
            // Idempotent: a second down for the same handle is a no-op.
            CascadeWiring.onHostBridgeDown(7)

            assertEquals(
                listOf("registerHostBridge", "unregisterHostBridge"),
                b.calls.map { it.name },
            )
            assertEquals(listOf<Any?>(7, "10.99.0.0/24"), b.calls[0].args)
        }
    }

    @Test fun `setEnabled(false) tears down registered state`() {
        val b = RecordingBridge()
        withBridge(b) {
            CascadeWiring.setEnabled(true)
            CascadeWiring.onJoinerStackUp(42, "10.50.0.0/24")
            CascadeWiring.onHostBridgeUp(7, "10.99.0.0/24")
            CascadeWiring.onHostBridgeUp(8, "10.99.1.0/24")

            b.calls.clear()
            CascadeWiring.setEnabled(false)

            // Tear-down sweeps every registered host bridge and the
            // joiner stack.
            val names = b.calls.map { it.name }.toSet()
            assertTrue(names.contains("unregisterHostBridge"),
                "must unregister host bridges: $names")
            assertTrue(names.contains("unregisterJoiner"),
                "must unregister joiner: $names")
            val hostUnregs = b.calls.count { it.name == "unregisterHostBridge" }
            assertEquals(2, hostUnregs)
            assertFalse(CascadeWiring.isEnabled())
        }
    }

    @Test fun `setEnabled is idempotent`() {
        val b = RecordingBridge()
        withBridge(b) {
            CascadeWiring.setEnabled(true)
            CascadeWiring.setEnabled(true)  // no-op
            CascadeWiring.onJoinerStackUp(42, "")
            CascadeWiring.setEnabled(false)
            CascadeWiring.setEnabled(false)  // no-op
            CascadeWiring.setEnabled(true)
            assertNull(CascadeWiring.snapshotState().joinerStackHandle)
        }
    }

    @Test fun `unionAllowedIpsFromUapi parses every allowed_ip line`() {
        val uapi1 = """
            private_key=aaaa
            public_key=bbbb
            allowed_ip=10.50.0.0/24
            allowed_ip=2001:db8::/64
            persistent_keepalive_interval=25
        """.trimIndent()
        val uapi2 = """
            public_key=cccc
            allowed_ip=10.51.0.0/24
            allowed_ip=10.50.0.0/24
        """.trimIndent()
        val csv = CascadeWiring.unionAllowedIpsFromUapi(listOf(uapi1, uapi2))
        val parts = csv.split(",").toSet()
        assertEquals(setOf("10.50.0.0/24", "2001:db8::/64", "10.51.0.0/24"), parts)
    }

    @Test fun `joiner-stack-down without joiner-up is a no-op`() {
        val b = RecordingBridge()
        withBridge(b) {
            CascadeWiring.setEnabled(true)
            CascadeWiring.onJoinerStackDown()
            CascadeWiring.onJoinerAllowedIpsChanged("10.50.0.0/24")
            assertTrue(b.calls.isEmpty(), "calls=${b.calls}")
        }
    }

    @Test fun `onJoinerInterfaceAddrsChanged routes through the bridge when enabled`() {
        // CASCADE-2 NAT — verify the new method threads the CSV
        // through to the bridge unchanged.  Bridge isn't asked
        // until cascade is enabled.
        val b = RecordingBridge()
        withBridge(b) {
            CascadeWiring.onJoinerInterfaceAddrsChanged("10.240.234.3,2001:db8::3")
            assertTrue(b.calls.isEmpty(),
                "disabled cascade must not call bridge: ${b.calls}")
            CascadeWiring.setEnabled(true)
            b.calls.clear()
            CascadeWiring.onJoinerInterfaceAddrsChanged("10.240.234.3,2001:db8::3")
            assertEquals(
                listOf("joinerInterfaceAddrsChanged"),
                b.calls.map { it.name },
            )
            assertEquals(
                listOf<Any?>("10.240.234.3,2001:db8::3"),
                b.calls[0].args,
            )
        }
    }

    @Test fun `snapshot reflects current state`() {
        val b = RecordingBridge()
        withBridge(b) {
            CascadeWiring.setEnabled(true)
            CascadeWiring.onJoinerStackUp(99, "10.50.0.0/24,10.51.0.0/24")
            CascadeWiring.onHostBridgeUp(7, "10.99.0.0/24")
            val snap = CascadeWiring.snapshotState()
            assertNotNull(snap.joinerStackHandle)
            assertEquals(99, snap.joinerStackHandle)
            assertEquals(setOf("10.50.0.0/24", "10.51.0.0/24"), snap.joinerAllowedIps)
            assertEquals(setOf(7), snap.hostBridges.keys)
            assertEquals(setOf("10.99.0.0/24"), snap.hostBridges[7])
        }
    }
}
