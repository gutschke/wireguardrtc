package com.gutschke.wgrtc.data

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.net.VpnService
import android.os.IBinder
import android.os.ParcelFileDescriptor
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.gutschke.wgrtc.service.JoinerVpnService
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * **the decisive test.**
 *
 * Drives the cgo + `//export` libwgbridge_native.so against a
 * real WG peer (the kernel-WG sandbox in `unshare -Urn` netns,
 * via `dev-env/sandbox-wg-server.sh`) — exactly the path that
 * triggered the gomobile-built bridge's
 * `runtime.bulkBarrierPreWrite: unaligned arguments` panic
 * (`JoinerHandshakeInstrumentedTest`).
 *
 * If this test passes:
 * - ** confirmed** — gomobile-bind's auto-generated
 * marshalling was the bug. cgo + `//export` is the fix.
 * Stage 3 (port the rest) is mechanical.
 *
 * If this test crashes with the same panic:
 * - ** confirmed** — Go 1.25's runtime is at fault
 * irrespective of build style. Need to escalate to
 * pinning the toolchain (deeper dependency-chain
 * wrangling), or close deferred.
 *
 * If this test fails differently:
 * - new failure mode, debug per its specifics.
 *
 * The test re-uses [JoinerVpnService.Builder.establish] for the
 * TUN fd (no other way to get one as an ordinary app), but then
 * routes the fd through [WgBridgeNative.nativeNewWithTunFd]
 * — entirely bypassing [RealWgBridgeBackend] / gomobile.
 *
 * Configured by the orchestrator via `am instrument -e cfgB64
 * <base64>` (see `dev-env/run-c2-handshake-test.sh`). Without
 * cfgB64 the test self-skips so a regular `am instrument -w` of
 * the whole suite doesn't fail spuriously.
 */
@RunWith(AndroidJUnit4::class)
class WgBridgeNativeHandshakeTest {

    private val ctx: Context get() = ApplicationProvider.getApplicationContext()
    @Volatile private var pfd: ParcelFileDescriptor? = null
    @Volatile private var nativeHandle: Int = 0

    @Before
    fun grantVpnConsent() {
        Runtime.getRuntime().exec(arrayOf(
            "sh", "-c",
            "appops set com.gutschke.wgrtc.debug ACTIVATE_VPN allow"
        )).waitFor()
    }

    @After
    fun tearDown() {
        if (nativeHandle > 0) {
            WgBridgeNative.nativeClose(nativeHandle)
            nativeHandle = 0
        }
        pfd?.close()
        pfd = null
        // Stop the VpnService (it has no other state)
        val intent = Intent(ctx, JoinerVpnService::class.java)
        intent.action = JoinerVpnService.ACTION_STOP
        ctx.startService(intent)
        Thread.sleep(200)
    }

    @Test
    fun handshakeViaCgoBridge() {
        val cfgB64 = InstrumentationRegistry.getArguments().getString("cfgB64")
        assumeTrue(
            "Skipping — pass `-e cfgB64 <base64>` from the orchestrator",
            !cfgB64.isNullOrBlank())
        val cfg = String(android.util.Base64.decode(cfgB64,
            android.util.Base64.DEFAULT))

        // Sanity — version round-trips. Surfaces .so load errors
        // before we burn time on the harder path.
        val ver = WgBridgeNative.nativeVersion()
        assertTrue("native version must be non-empty: '$ver'", ver.isNotEmpty())

        // Get a TUN fd via the existing JoinerVpnService. The
        // service's start() also wires up wireguard-go via the
        // gomobile path — but we don't call that here. Instead
        // we build the TUN ourselves and hand the fd to the
        // native bridge.
        val parsed = JoinerVpnConfig.parse(cfg)
        val service = bindAndAwait()
        pfd = service.establishTunForTest(parsed)
            ?: error("Builder.establish() returned null — VPN consent missing?")
        val fd = pfd!!.detachFd()

        // Open the bridge via cgo + //export. This is the path
        // that hits the alignment panic when wireguard-go starts
        // sending packets — IF gomobile was the cause.
        nativeHandle = WgBridgeNative.nativeNewWithTunFd(fd)
        assertTrue("nativeNewWithTunFd returned $nativeHandle " +
            "(expected positive handle)", nativeHandle > 0)

        // Render the wg-quick text into UAPI. The same
        // WgQuickUapi parser the rest of the joiner path uses.
        val uapi = WgQuickUapi.render(cfg)
        val configureRc = WgBridgeNative.nativeConfigureUAPI(nativeHandle, uapi)
        assertEquals(0, configureRc)

        // Wait up to 15 s for a handshake. This is the moment of
        // truth: persistent_keepalive=5 fires immediately, the
        // first WG init goes out, wireguard-go starts processing
        // packets — exactly the path that panics under gomobile.
        val deadline = System.currentTimeMillis() + 15_000
        var lastDump: String? = null
        while (System.currentTimeMillis() < deadline) {
            val dump = WgBridgeNative.nativeSnapshotUAPI(nativeHandle)
            lastDump = dump
            if (dump != null) {
                val parsedDump = UapiStatsParser.parse(dump)
                val recent = parsedDump.mostRecentHandshakeEpochMs
                if (recent != null && recent > 0) {
                    // Handshake completed! Stage 2 passes,
                    // confirmed.
                    return
                }
            }
            Thread.sleep(250)
        }
        org.junit.Assert.fail(
            "no handshake within 15 s — wireguard-go didn't reach the " +
                "sandbox peer. last UAPI dump:\n$lastDump")
    }

    private fun bindAndAwait(): JoinerVpnService {
        val latch = CountDownLatch(1)
        var binder: JoinerVpnService.LocalBinder? = null
        val conn = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName?, b: IBinder?) {
                binder = b as JoinerVpnService.LocalBinder
                latch.countDown()
            }
            override fun onServiceDisconnected(name: ComponentName?) {}
        }
        val intent = Intent(ctx, JoinerVpnService::class.java)
        check(ctx.bindService(intent, conn, Context.BIND_AUTO_CREATE))
        check(latch.await(5, TimeUnit.SECONDS))
        return binder!!.getService()
    }
}
