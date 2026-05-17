package com.gutschke.wgrtc.data

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * §13 layer-3 kill-switch gate at the [CascadeWiring] layer.  When
 * `setEnabled(false)` is in effect, every `on*` event is a no-op
 * AND any previously-registered host bridges + joiner stack are
 * torn down synchronously.  Re-enabling lets future events
 * register again.
 *
 * Pinned here because production wires
 * `SettingsStore.cascadeForcedOffFlow` to `CascadeWiring.setEnabled`
 * via WgrtcApp's collector — the gate's correctness is what makes
 * the user-side toggle a meaningful kill-switch.  Without this
 * test, a refactor that re-orders or weakens the
 * setEnabled(false) tear-down silently ships.
 */
class CascadeForcedOffGateTest {

    /** Recording bridge — mirrors the helper used in
     *  CascadeWiringTest. */
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

    @Test fun `setEnabled false tears down ALL host bridges synchronously`() {
        // The kill-switch's load-bearing property: when the user
        // flips it on (in our terms, setEnabled(false)), every
        // currently-active host bridge becomes cascade-less
        // immediately.  No "next reconnect" delay.
        val b = RecordingBridge()
        withBridge(b) {
            CascadeWiring.setEnabled(true)
            CascadeWiring.onHostBridgeUp(7, "10.99.0.0/24")
            CascadeWiring.onHostBridgeUp(8, "10.50.0.0/24")
            CascadeWiring.onHostBridgeUp(9, "192.168.5.0/24")
            // Sanity: all three registered.
            val regs = b.calls.count { it.name == "registerHostBridge" }
            assertEquals(3, regs)
            b.calls.clear()

            // Kill-switch fires.
            CascadeWiring.setEnabled(false)

            // Every host bridge gets explicitly unregistered.
            val unregs = b.calls.filter { it.name == "unregisterHostBridge" }
            assertEquals(3, unregs.size, "expected 3 unregisters, got $unregs")
        }
    }

    @Test fun `setEnabled false tears down the joiner stack synchronously`() {
        val b = RecordingBridge()
        withBridge(b) {
            CascadeWiring.setEnabled(true)
            CascadeWiring.onJoinerStackUp(42, "10.240.234.0/24")
            assertTrue(b.calls.any { it.name == "registerJoiner" })
            b.calls.clear()

            CascadeWiring.setEnabled(false)

            assertTrue(b.calls.any { it.name == "unregisterJoiner" },
                "joiner stack must be unregistered when wiring disables: ${b.calls}")
        }
    }

    @Test fun `further on-events after setEnabled false are no-ops`() {
        // Confirms the gate stays closed: even a Tunnel that comes
        // up while the kill-switch is engaged does NOT register.
        // This is the protection against "a CASCADE-2 regression
        // re-fires when the user reconnects" footgun.
        val b = RecordingBridge()
        withBridge(b) {
            CascadeWiring.setEnabled(false)  // kill-switch on
            CascadeWiring.onHostBridgeUp(7, "10.99.0.0/24")
            CascadeWiring.onJoinerStackUp(42, "10.240.234.0/24")
            CascadeWiring.onJoinerAllowedIpsChanged("10.240.234.0/24")
            // No registrations should have happened.
            assertEquals(emptyList<RecordingBridge.Call>(), b.calls,
                "kill-switch must block subsequent registrations: ${b.calls}")
        }
    }

    @Test fun `setEnabled true allows subsequent on-events to register`() {
        // Reverse direction: after the user toggles the kill-switch
        // off, new registrations work again.  Previously-registered
        // bridges that were torn down stay torn down (the caller
        // must re-fire onHostBridgeUp via reapplyCascadeForActiveSlots
        // to bring them back) — pinned by the empty initial state.
        val b = RecordingBridge()
        withBridge(b) {
            CascadeWiring.setEnabled(false)
            CascadeWiring.setEnabled(true)
            CascadeWiring.onHostBridgeUp(7, "10.99.0.0/24")
            assertTrue(b.calls.any { it.name == "registerHostBridge" })
        }
    }

    @Test fun `idempotent same-value setEnabled does nothing`() {
        // The flow-collector pattern relies on
        // distinctUntilChanged semantics; pin that two consecutive
        // setEnabled(false) calls produce only ONE tear-down sweep.
        val b = RecordingBridge()
        withBridge(b) {
            CascadeWiring.setEnabled(true)
            CascadeWiring.onHostBridgeUp(7, "10.99.0.0/24")
            b.calls.clear()
            CascadeWiring.setEnabled(false)
            val firstSweep = b.calls.size
            b.calls.clear()
            CascadeWiring.setEnabled(false)  // already off; no-op
            assertEquals(0, b.calls.size,
                "redundant setEnabled(false) must be a no-op")
            assertTrue(firstSweep > 0,
                "first setEnabled(false) must have torn down")
        }
    }
}
