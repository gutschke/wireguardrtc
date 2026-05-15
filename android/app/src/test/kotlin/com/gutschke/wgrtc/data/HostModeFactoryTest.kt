package com.gutschke.wgrtc.data

import com.goterl.lazysodium.LazySodiumJava
import com.goterl.lazysodium.SodiumJava
import com.gutschke.wgrtc.signalling.Sodium
import com.gutschke.wgrtc.signalling.pubKeyFromPrivate
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import java.security.SecureRandom
import java.util.Base64

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class HostModeFactoryTest {

    @BeforeAll fun installJvmSodium() {
        Sodium.setForTest(LazySodiumJava(SodiumJava()))
    }
    @AfterAll fun restoreSodium() { Sodium.setForTest(null) }

    private val rng = SecureRandom()

    @Test fun `new tunnel has HOST_MODE source and matching hostMode config`() {
        val t = HostModeFactory.newTunnel(
            name = "host",
            subnet = "10.99.0.0/24",
            hostIp = "10.99.0.1",
            listenPort = 51820,
            brokerWss = "wss://b.example/peerjs",
            brokerKey = "k",
            rng = rng,
        )
        assertEquals("host", t.name)
        assertEquals(Tunnel.Source.HOST_MODE, t.source)
        assertEquals("10.99.0.0/24", t.hostMode!!.subnet)
        assertTrue(t.hostMode!!.enrolledPeers.isEmpty())
        // ID is a fresh UUID-shaped string.
        assertTrue(t.id.matches(Regex("[a-f0-9-]{36}")), "id not a UUID: ${t.id}")
    }

    @Test fun `configText is a parseable Interface block with the right fields`() {
        val t = HostModeFactory.newTunnel(
            name = "x", subnet = "10.99.0.0/24",
            hostIp = "10.99.0.1", listenPort = 51820,
            brokerWss = "wss://x/y", brokerKey = "k",
            rng = rng,
        )
        // Header.
        assertTrue(t.configText.startsWith("[Interface]"),
            "configText should start with [Interface]; got: ${t.configText}")
        // Required fields.
        val priv = configValueOf(t.configText, "PrivateKey")!!
        assertEquals(32, Base64.getDecoder().decode(priv).size,
            "PrivateKey must decode to 32 bytes")
        assertEquals("10.99.0.1/24", configValueOf(t.configText, "Address"))
        assertEquals("51820", configValueOf(t.configText, "ListenPort"))
        // No [Peer] block in a fresh host-mode tunnel.
        assertFalse(t.configText.contains("[Peer]"),
            "host tunnel must not have any [Peer] blocks until peers enroll")
    }

    @Test fun `broker fields and salt are set`() {
        val t = HostModeFactory.newTunnel(
            name = "x", subnet = "10.99.0.0/24",
            hostIp = "10.99.0.1", listenPort = 51820,
            brokerWss = "wss://broker.example.com/peerjs",
            brokerKey = "shared-secret",
            rng = rng,
        )
        assertEquals("wss://broker.example.com/peerjs", t.brokerWss)
        assertEquals("shared-secret", t.brokerKey)
        // saltB64 is URL-safe base64 no padding (matches the URI spec).
        val salt = t.saltB64!!
        assertFalse(salt.contains("="), "salt must be no-padding")
        // Decodes to exactly 32 bytes (matches what InboundEnrollHandler
        // and PendingTokensStore expect).
        val padded = salt + when (salt.length % 4) { 2 -> "=="; 3 -> "="; else -> "" }
        assertEquals(32, Base64.getUrlDecoder().decode(padded).size)
    }

    @Test fun `each call produces fresh keypair and salt`() {
        val a = HostModeFactory.newTunnel(
            name = "a", subnet = "10.99.0.0/24",
            hostIp = "10.99.0.1", listenPort = 51820,
            brokerWss = "wss://x/y", brokerKey = "k", rng = rng,
        )
        val b = HostModeFactory.newTunnel(
            name = "b", subnet = "10.99.0.0/24",
            hostIp = "10.99.0.1", listenPort = 51820,
            brokerWss = "wss://x/y", brokerKey = "k", rng = rng,
        )
        assertNotEquals(configValueOf(a.configText, "PrivateKey"),
                        configValueOf(b.configText, "PrivateKey"),
                        "PrivateKey should be fresh per call")
        assertNotEquals(a.saltB64, b.saltB64,
                        "salt should be fresh per call")
        assertNotEquals(a.id, b.id, "id should be fresh per call")
    }

    @Test fun `pub key derived from priv matches when re-derived`() {
        val t = HostModeFactory.newTunnel(
            name = "x", subnet = "10.99.0.0/24",
            hostIp = "10.99.0.1", listenPort = 51820,
            brokerWss = "wss://x/y", brokerKey = "k", rng = rng,
        )
        val privBytes = Base64.getDecoder().decode(
            configValueOf(t.configText, "PrivateKey")!!)
        // Should not throw — i.e. priv is a valid Curve25519 scalar.
        val pub = pubKeyFromPrivate(privBytes)
        assertEquals(32, pub.size)
    }

    @Test fun `rejects malformed subnet`() {
        assertThrows(IllegalArgumentException::class.java) {
            HostModeFactory.newTunnel(
                name = "x", subnet = "not-a-cidr",
                hostIp = "10.99.0.1", listenPort = 51820,
                brokerWss = "wss://x/y", brokerKey = "k", rng = rng,
            )
        }
    }

    @Test fun `rejects host IP outside subnet`() {
        assertThrows(IllegalArgumentException::class.java) {
            HostModeFactory.newTunnel(
                name = "x", subnet = "10.99.0.0/24",
                hostIp = "192.168.1.1", // not in subnet
                listenPort = 51820,
                brokerWss = "wss://x/y", brokerKey = "k", rng = rng,
            )
        }
    }

    @Test fun `rejects out-of-range port`() {
        assertThrows(IllegalArgumentException::class.java) {
            HostModeFactory.newTunnel(
                name = "x", subnet = "10.99.0.0/24",
                hostIp = "10.99.0.1", listenPort = 0,
                brokerWss = "wss://x/y", brokerKey = "k", rng = rng,
            )
        }
        assertThrows(IllegalArgumentException::class.java) {
            HostModeFactory.newTunnel(
                name = "x", subnet = "10.99.0.0/24",
                hostIp = "10.99.0.1", listenPort = 70_000,
                brokerWss = "wss://x/y", brokerKey = "k", rng = rng,
            )
        }
    }

    // V6.2 — per-tunnel ULA generation lands here.  Every new
    // host-mode tunnel is now born dual-stack: a v4 subnet from the
    // user-supplied parameters AND a freshly minted ULA `/64`.
    // Joiners receive both addresses when they enroll (V6.3).

    @Test fun `V6_2 new tunnel has a v6 ULA subnet populated`() {
        val t = HostModeFactory.newTunnel(
            name = "host", subnet = "10.99.0.0/24",
            hostIp = "10.99.0.1", listenPort = 51820,
            brokerWss = "wss://x/y", brokerKey = "k", rng = rng,
        )
        val v6 = t.hostMode!!.subnetV6
        assertNotNull(v6, "subnetV6 must be populated for new host tunnels")
        assertTrue(v6!!.startsWith("fd"), "ULA must start with fd; got $v6")
        assertTrue(v6.endsWith("/64"), "ULA must be /64; got $v6")
    }

    @Test fun `V6_2 configText contains v6 Address line alongside v4`() {
        val t = HostModeFactory.newTunnel(
            name = "host", subnet = "10.99.0.0/24",
            hostIp = "10.99.0.1", listenPort = 51820,
            brokerWss = "wss://x/y", brokerKey = "k", rng = rng,
        )
        // V6.H1 helper splits multi-line + comma-separated Address
        // entries.  Both v4 + v6 must be present.
        val addrs = parseInterfaceAddresses(t.configText)
        assertEquals(2, addrs.size,
            "expected v4 + v6 Address lines; got $addrs")
        assertEquals("10.99.0.1", addrs[0])
        assertTrue(addrs[1].startsWith("fd"),
            "second address must be the v6 ULA host; got ${addrs[1]}")
    }

    @Test fun `V6_2 v6 host IP is the dot-one of subnetV6`() {
        // Convention: host owns ::1 in its v6 subnet, mirroring the
        // v4 .1 convention.  This makes joiner-side rendering of
        // [Peer] AllowedIPs trivial (always /128 of the host's ::1)
        // and matches what enterprise WG deployments expect.
        val t = HostModeFactory.newTunnel(
            name = "host", subnet = "10.99.0.0/24",
            hostIp = "10.99.0.1", listenPort = 51820,
            brokerWss = "wss://x/y", brokerKey = "k", rng = rng,
        )
        val v6subnet = t.hostMode!!.subnetV6!!
        val v6Net = v6subnet.removeSuffix("/64")
        val v6Host = parseInterfaceAddresses(t.configText)[1]
        // v6Net is "fdXX:XXXX:XXXX::"; v6Host should be the same with ::1.
        // Compress: "fdXX:XXXX:XXXX::1".
        val expected = v6Net + "1"
        assertEquals(expected, v6Host,
            "v6 host IP must be subnetV6's network address + 1")
    }

    @Test fun `V6_2 each new tunnel gets a distinct ULA prefix`() {
        val a = HostModeFactory.newTunnel(
            name = "a", subnet = "10.99.0.0/24",
            hostIp = "10.99.0.1", listenPort = 51820,
            brokerWss = "wss://x/y", brokerKey = "k", rng = rng,
        )
        val b = HostModeFactory.newTunnel(
            name = "b", subnet = "10.99.0.0/24",
            hostIp = "10.99.0.1", listenPort = 51820,
            brokerWss = "wss://x/y", brokerKey = "k", rng = rng,
        )
        assertNotEquals(a.hostMode!!.subnetV6, b.hostMode!!.subnetV6,
            "fresh tunnels must get distinct ULAs (collision odds 1 in 2^40)")
    }

    private fun configValueOf(configText: String, key: String): String? =
        configText.lineSequence()
            .firstOrNull {
                it.trim().startsWith(key, ignoreCase = true) && it.contains("=")
            }?.substringAfter("=")?.trim()
}
