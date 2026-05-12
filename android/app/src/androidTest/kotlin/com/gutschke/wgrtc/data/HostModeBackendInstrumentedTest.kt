package com.gutschke.wgrtc.data

import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.util.Base64
import java.util.UUID

/**
 * Instrumented (on-device / on-emulator) tests for [HostModeBackend].
 *
 * **Why these are instrumented and not JVM unit tests:** the bugs
 * they characterise live in the gomobile/JNI binding layer, not in
 * `wireguard-go` itself. Plain Linux Go tests in `android/wgbridge/`
 * already exercise the WG-side semantics; the close+reopen panic
 * (`runtime.cgocallback.abi0+112` /
 * `bulkBarrierPreWrite: unaligned arguments`) only fires when the
 * Bridge is reached via JNI.
 *
 * Run with:
 * ```
 * ANDROID_ADB_SERVER_ADDRESS=198.51.100.118 \
 * ./gradlew :app:connectedDebugAndroidTest \
 * --tests com.gutschke.wgrtc.data.HostModeBackendInstrumentedTest
 * ```
 *
 * (See `memory/the dev-env README` for emulator details.)
 *
 * Each test resets the [GoRuntimeGuard] flags so an earlier test
 * doesn't poison a later one. The bridge load itself can't be
 * undone — once `libgojni.so` is in the address space it stays —
 * but HostModeBackend's per-instance state is reset between
 * tests.
 */
@RunWith(AndroidJUnit4::class)
class HostModeBackendInstrumentedTest {

    private val parentJob = SupervisorJob()
    private val parentScope = CoroutineScope(Dispatchers.Default + parentJob)

    private val privKey = ByteArray(32) { (it + 1).toByte() }
    private val privB64 = Base64.getEncoder().encodeToString(privKey)
    private val peerKey = ByteArray(32) { 0xAA.toByte() }
    private val peerB64 = Base64.getEncoder().encodeToString(peerKey)
    private val peer2Key = ByteArray(32) { 0xBB.toByte() }
    private val peer2B64 = Base64.getEncoder().encodeToString(peer2Key)

    // GoRuntimeGuard was deleted in (no second Go runtime
    // to guard against now that wireguard-android is gone).

    /**
     * Sanity check that the test harness is actually running in the
     * Android process and can reach wgbridge's JNI. If this passes,
     * `libgojni.so` was loaded; the lifecycle tests below are
     * exercising the real bridge.
     */
    @Test
    fun jniSmokeProbe() {
        val version = RealWgBridgeBackendNative.nativeVersion()
        assertTrue("wgbridge native version should be non-empty: '$version'",
            version.isNotEmpty())
        android.util.Log.i("wgrtc-androidtest",
            "JNI smoke probe OK; wgbridge version=$version")
    }

    /**
     * smoke probe: the new `openWithTunFd(fd, mtu)` factory
     * should be reachable via the gomobile binding. We pass an
     * invalid fd to dodge the need for a real VpnService TUN —
     * the Go side rejects `fd < 0` cleanly. All we want to
     * confirm here is that the JNI symbol exists; happy-path
     * VpnService integration is 's job.
     */
    @Test
    fun tunFdConstructorIsReachableViaJni() {
        try {
            RealWgBridgeBackendNative.openWithTunFd(fd = -1, mtu = 1420)
            org.junit.Assert.fail("openWithTunFd(-1) should error")
        } catch (e: Exception) {
            assertTrue("error should mention the bad fd: '${e.message}'",
                e.message?.contains("invalid fd") == true ||
                    e.message?.contains("fd: -1") == true ||
                    e.message?.contains("-1") == true)
        }
    }
    @After fun tearDown() {
        runBlocking {
            // Don't try to teardown — that calls the close path which
            // is exactly what wants to avoid. Cancel the scope
            // and let the bridge get GC'd at process end.
        }
        parentJob.cancel()
    }

    private fun pickPort(): Int = 49000 + (System.nanoTime() % 5000).toInt()

    private fun hostTunnel(
        id: String = UUID.randomUUID().toString(),
        listenPort: Int = pickPort(),
        peers: List<EnrolledPeer> = listOf(
            EnrolledPeer(peerB64, "10.99.0.2", "g", 1L)
        ),
    ): Tunnel = Tunnel(
        id = id,
        name = "host-test",
        configText = """
            [Interface]
            PrivateKey = $privB64
            Address = 10.99.0.1/24
            ListenPort = $listenPort
        """.trimIndent(),
        source = Tunnel.Source.HOST_MODE,
        hostMode = HostModeConfig(
            subnet = "10.99.0.0/24",
            enrolledPeers = peers,
        ),
    )

    private fun realFactory(): WgBridgeBackendFactory =
        WgBridgeBackendFactory { localAddr, mtu, listenPort ->
            RealWgBridgeBackendNative.open(localAddr, mtu, listenPort)
        }

    /**
     * lifecycle reproducer: start → stop → start of the SAME
     * tunnel. Before this triggered the
     * `bulkBarrierPreWrite: unaligned arguments` panic on the
     * user's Android phone because each start opened a fresh
     * wireguard-go device, and the second `device.NewDevice` in
     * the same JNI process panicked. After the second
     * `start()` reuses the same bridge via UAPI pause/resume —
     * factory.open is called exactly once across the whole loop.
     */
    @Test
    fun startStopStartCycleDoesNotCrash() = runBlocking<Unit> {
        val be = HostModeBackend(realFactory(), parentScope)
        val tunnel = hostTunnel()

        be.start(tunnel)
        assertNotNull("first start failed to register active tunnel",
            be.activeTunnelId)

        be.stop()
        assertNull("stop should clear activeTunnelId", be.activeTunnelId)

        // The crash, if it happens, fires here:
        be.start(tunnel)
        assertNotNull("second start failed to register active tunnel",
            be.activeTunnelId)

        // Hammer it a few more times — the user's repro sometimes
        // needed a second cycle. Each iteration must remain crash-free.
        repeat(3) {
            be.stop()
            be.start(tunnel)
        }

        be.stop()
    }

    /**
     * ABI characterisation: deliberately exercise the OLD
     * close+recreate path that crashed on the user's Android phone
     * (arm64, Android 16) with
     * `runtime.cgocallback.abi0+112` /
     * `bulkBarrierPreWrite: unaligned arguments`.
     *
     * Calls [RealWgBridgeBackendNative.open] → close → open in a tight
     * loop. If this passes on the emulator (x86_64, Android 14)
     * but fails on Pixel-class hardware, we've localised the
     * panic to arm64 ABI / 16 KB-page-size territory. If it
     * panics here too, the pause/resume mitigation is
     * universally necessary.
     *
     * Either result is informative. This test is allowed to
     * "succeed" — the assertion is that the runner doesn't crash
     * the test process; pinning the bug's ABI scope happens at
     * the test-result-comparison level, not inside the test.
     */
    @Test
    fun rawCloseRecreateLifecycle_smokeTest() {
        repeat(3) {
            val backend = RealWgBridgeBackendNative.open("10.99.0.1", 1420, pickPort())
            backend.configureUapi("private_key=${"00".repeat(32)}\nlisten_port=0\n")
            backend.close()
            // Brief pause to let goroutines / timers from the
            // previous instance settle before the next New().
            Thread.sleep(50)
        }
    }

    /**
     * part 2: revoke a peer + add a new one, then verify the
     * old peer is gone from wireguard-go's internal table. The
     * regression fired when [HostModeUapi.render] omitted
     * `replace_peers=true` — `IpcSet`'s merge semantics kept the
     * revoked peer alive on the host side.
     */
    @Test
    fun reconfigureDropsRevokedPeerFromWgGoTable() = runBlocking<Unit> {
        val be = HostModeBackend(realFactory(), parentScope)
        val tunnel1 = hostTunnel(peers = listOf(
            EnrolledPeer(peerB64, "10.99.0.2", "g1", 1L)))

        be.start(tunnel1)

        // Reconfigure with peer2 ONLY — peer1 should disappear.
        val tunnel2 = tunnel1.copy(
            hostMode = tunnel1.hostMode!!.copy(
                enrolledPeers = listOf(
                    EnrolledPeer(peer2B64, "10.99.0.3", "g2", 2L))))
        be.reconfigure(tunnel2)

        // Sample the wireguard-go state. Hex of peer1 should NOT
        // appear; hex of peer2 SHOULD. Convert via the same path
        // the parser uses so the assertion isn't sensitive to
        // case / formatting subtleties.
        val stats = be.snapshotStats()
        assertNotNull("snapshotStats returned null after reconfigure", stats)
        val peers = stats!!.peers.keys
        assertTrue("revoked peer $peerB64 still in wg-go table: $peers",
            peerB64 !in peers)
        assertTrue("new peer $peer2B64 missing from wg-go table: $peers",
            peer2B64 in peers)

        be.stop()
    }
}
