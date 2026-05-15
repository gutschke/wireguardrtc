package com.gutschke.wgrtc.service

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.IBinder
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.gutschke.wgrtc.data.Cidr
import com.gutschke.wgrtc.data.JoinerVpnConfig
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * D4.P3 spike — does kernel TCP / UDP socket state survive a
 * `VpnService.Builder.establish()` rebuild with identical addresses
 * and routes? This is the load-bearing UX assumption for joiner-N's
 * reconfigure model (see `docs/cascade-n-design.md` §Reconfigure):
 * adding or removing a joiner forces a full establish-rebuild, and
 * we claim that connections through *unrelated* joiners survive
 * because kernel sockets are 4-tuple-keyed and don't bind to TUN
 * identity.
 *
 * **Narrow scope.** The probes here use `10.250.0.0/24` so the
 * VpnService routes don't capture adb's own traffic (per
 * `feedback_vpn_toggle_kills_adb.md`). The TUN address is
 * `10.250.0.1/32` — a narrow joiner-style address with no real
 * peer reachable; the test never sends actual data through the
 * tunnel. What it DOES is exercise the kernel's response to
 * back-to-back `Builder.establish()` calls with identical
 * configuration, and confirm:
 *
 *   - The address stays bound across the swap (probed by binding
 *     a UDP socket to it twice, before and after).
 *   - An open TCP listener bound to the address survives the swap
 *     (probed by accepting a fresh connection after the rebuild).
 *   - An ESTABLISHED TCP connection survives the swap (the
 *     load-bearing case — kernel TCP state machine is preserved).
 *
 * **What this DOESN'T cover.** Routing through the tunnel to a
 * remote network — that requires a peer + wireguard-go up, which
 * is the `D4.J5` instrumented test, not P3. P3's only question is
 * "does the kernel keep socket state alive when the TUN swaps".
 *
 * Run via:
 * ```
 * ANDROID_ADB_SERVER_ADDRESS=10.10.0.118 \
 * ./gradlew :app:connectedDebugAndroidTest \
 *   --tests com.gutschke.wgrtc.service.D4P3TcpSurvivesRebuildTest
 * ```
 */
@RunWith(AndroidJUnit4::class)
class D4P3TcpSurvivesRebuildTest {

    private val ctx: Context get() = ApplicationProvider.getApplicationContext()

    /** VPN-address config used by every probe.  `10.250.0.0/24` is
     * a documentation-safe range (RFC 1918 sub-allocation we don't
     * use elsewhere) that won't collide with adb or the dev LAN. */
    private fun probeConfig() = JoinerVpnConfig(
        addresses = listOf(Cidr("10.250.0.1", 32)),
        routes = listOf(Cidr("10.250.0.0", 24)),
        mtu = 1420,
    )

    @Before
    fun grantVpnConsent() {
        // Same `appops` trick as JoinerVpnServiceInstrumentedTest —
        // bypasses the system consent dialog so the test can call
        // Builder.establish without UI.
        Runtime.getRuntime().exec(arrayOf(
            "sh", "-c",
            "appops set com.gutschke.wgrtc.debug ACTIVATE_VPN allow"
        )).waitFor()
    }

    @After
    fun tearDown() {
        // Belt-and-braces — kill the service so subsequent tests
        // don't inherit our TUN.
        val intent = Intent(ctx, JoinerVpnService::class.java)
        intent.action = JoinerVpnService.ACTION_STOP
        ctx.startService(intent)
        Thread.sleep(200)
    }

    /**
     * Probe 1 — address binding survives.  Bind a UDP socket to
     * `10.250.0.1:0` before AND after a rebuild; both binds must
     * succeed. If the kernel un-binds the address on the swap, the
     * second `bind()` returns EADDRNOTAVAIL.
     */
    @Test
    fun probe1_addressRemainsBoundAcrossRebuild() {
        val service = bindAndAwait()
        val cfg = probeConfig()

        val pfd1 = service.establishTunForTest(cfg)
        assertNotNull("first establish() returned null — VPN consent issue?", pfd1)

        DatagramSocket(InetSocketAddress("10.250.0.1", 0)).use { sock1 ->
            assertNotNull("socket bound before rebuild has no local address",
                sock1.localAddress)
            val localPort1 = sock1.localPort

            // Re-establish with identical config.
            val pfd2 = service.establishTunForTest(cfg)
            assertNotNull("second establish() returned null", pfd2)

            // Bind a fresh socket — confirms the address is still
            // recognised post-swap.
            DatagramSocket(InetSocketAddress("10.250.0.1", 0)).use { sock2 ->
                assertNotNull("socket bound after rebuild has no local address",
                    sock2.localAddress)
                // The original sock1 should still report the same
                // bound state. If the kernel orphaned it, getLocalPort
                // typically returns 0 or -1.
                assertEquals("sock1 lost its bound port across rebuild",
                    localPort1, sock1.localPort)
            }

            pfd1?.close()
            pfd2?.close()
        }
    }

    /**
     * Probe 2 — TCP listener accept after rebuild. Open a TCP
     * server bound to the VPN address, rebuild, then connect to
     * it. The connect path is loopback (same process) so it
     * doesn't actually traverse `tun0`; the question being probed
     * is whether the LISTEN socket survives.
     */
    @Test
    fun probe2_tcpListenerAcceptsAfterRebuild() {
        val service = bindAndAwait()
        val cfg = probeConfig()

        val pfd1 = service.establishTunForTest(cfg)
        assertNotNull(pfd1)

        ServerSocket().use { server ->
            server.reuseAddress = true
            server.bind(InetSocketAddress("10.250.0.1", 0))
            val port = server.localPort
            server.soTimeout = 5000

            // Rebuild BEFORE any client connects.
            val pfd2 = service.establishTunForTest(cfg)
            assertNotNull(pfd2)

            // Now connect a client.  This succeeds only if:
            //   (a) the address is still bound, and
            //   (b) the kernel didn't tear down the listen queue.
            val accepted = CountDownLatch(1)
            val acceptedRef = arrayOfNulls<Socket>(1)
            val acceptThread = Thread {
                try {
                    acceptedRef[0] = server.accept()
                } catch (e: Throwable) {
                    // accept timed out or the listener died
                } finally {
                    accepted.countDown()
                }
            }.apply { start() }

            val client = Socket()
            client.connect(InetSocketAddress("10.250.0.1", port), 3000)
            assertTrue("server.accept() didn't fire within 5s of rebuild — " +
                "the listen socket likely got torn down during establish()",
                accepted.await(5, TimeUnit.SECONDS))
            assertNotNull(acceptedRef[0])

            client.close()
            acceptedRef[0]?.close()
            acceptThread.join(1000)

            pfd1?.close()
            pfd2?.close()
        }
    }

    /**
     * Probe 3 — the load-bearing case.  Open a TCP connection
     * BEFORE the rebuild, then verify it still passes bytes
     * AFTER the rebuild. If this fails the entire reconfigure-by-
     * rebuild model is wrong and we need a different strategy
     * (e.g. socketpair-based packet pump that survives in-process).
     */
    @Test
    fun probe3_establishedTcpConnectionSurvivesRebuild() {
        val service = bindAndAwait()
        val cfg = probeConfig()

        val pfd1 = service.establishTunForTest(cfg)
        assertNotNull(pfd1)

        ServerSocket().use { server ->
            server.reuseAddress = true
            server.bind(InetSocketAddress("10.250.0.1", 0))
            val port = server.localPort
            server.soTimeout = 5000

            val accepted = CountDownLatch(1)
            val acceptedRef = arrayOfNulls<Socket>(1)
            val acceptThread = Thread {
                try {
                    acceptedRef[0] = server.accept()
                } finally {
                    accepted.countDown()
                }
            }.apply { start() }

            val client = Socket()
            client.connect(InetSocketAddress("10.250.0.1", port), 3000)
            assertTrue("server.accept() should fire before rebuild",
                accepted.await(5, TimeUnit.SECONDS))
            val server2 = acceptedRef[0]!!

            // Send 'A' before the rebuild.
            client.getOutputStream().write('A'.code)
            client.getOutputStream().flush()
            val readBefore = server2.getInputStream().read()
            assertEquals('A'.code, readBefore)

            // **The rebuild.**
            val pfd2 = service.establishTunForTest(cfg)
            assertNotNull(pfd2)

            // Send 'B' AFTER the rebuild. If kernel TCP state was
            // torn down with the old TUN, write() or read() would
            // raise (RST → IOException, or read returns -1).
            try {
                client.getOutputStream().write('B'.code)
                client.getOutputStream().flush()
            } catch (t: Throwable) {
                throw AssertionError("write to surviving TCP socket " +
                    "raised after rebuild: ${t.javaClass.simpleName}: " +
                    "${t.message}", t)
            }
            server2.soTimeout = 3000
            val readAfter = try {
                server2.getInputStream().read()
            } catch (t: Throwable) {
                throw AssertionError("read from surviving TCP socket " +
                    "raised after rebuild: ${t.javaClass.simpleName}: " +
                    "${t.message}", t)
            }
            assertEquals("TCP byte didn't survive the rebuild",
                'B'.code, readAfter)

            client.close()
            server2.close()
            acceptThread.join(1000)
            pfd1?.close()
            pfd2?.close()
        }
    }

    /**
     * Probe 4 — UDP socket flow after rebuild. UDP is connectionless
     * but a bound socket can still send. If the address survives,
     * send() succeeds; if not, EADDRNOTAVAIL. We send a datagram
     * to a destination INSIDE the route (10.250.0.2) — there's no
     * receiver so we don't expect a reply, just that send() doesn't
     * raise.
     */
    @Test
    fun probe4_udpSendAfterRebuildDoesNotRaiseAddrUnavailable() {
        val service = bindAndAwait()
        val cfg = probeConfig()

        val pfd1 = service.establishTunForTest(cfg)
        assertNotNull(pfd1)

        DatagramSocket(InetSocketAddress("10.250.0.1", 0)).use { sock ->
            // Pre-rebuild sanity send.
            sock.send(DatagramPacket(
                "x".toByteArray(), 1,
                InetSocketAddress("10.250.0.2", 9999)))

            val pfd2 = service.establishTunForTest(cfg)
            assertNotNull(pfd2)

            try {
                sock.send(DatagramPacket(
                    "y".toByteArray(), 1,
                    InetSocketAddress("10.250.0.2", 9999)))
            } catch (t: Throwable) {
                throw AssertionError("UDP send raised after rebuild — " +
                    "address likely got un-bound from tun0: " +
                    "${t.javaClass.simpleName}: ${t.message}", t)
            }

            pfd1?.close()
            pfd2?.close()
        }
    }

    /** Bind to JoinerVpnService and block until LocalBinder fires. */
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
        check(ctx.bindService(intent, conn, Context.BIND_AUTO_CREATE)) {
            "bindService returned false"
        }
        check(latch.await(5, TimeUnit.SECONDS)) {
            "LocalBinder never connected"
        }
        return binder!!.getService()
    }
}
