package com.gutschke.wgrtc.signalling

import com.goterl.lazysodium.LazySodiumJava
import com.goterl.lazysodium.SodiumJava
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import java.util.Base64

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class SasEnrollInfoTest {

    @BeforeAll fun installJvmSodium() {
        Sodium.setForTest(LazySodiumJava(SodiumJava()))
    }
    @AfterAll fun restoreSodium() { Sodium.setForTest(null) }

    private val key = ByteArray(32) { 7 }
    private val now = 1_700_000_000L
    private val pubkey32 = ByteArray(32) { it.toByte() }
    private val pubkeyB64: String = Base64.getEncoder().encodeToString(pubkey32)

    // ─── Joiner round-trip ────────────────────────────────────────

    @Test fun `joiner info round-trips through encode then decode`() {
        val info = JoinerEnrollInfo(
            timestamp = now,
            wgPubkeyB64 = pubkeyB64,
            deviceName = "Android phone",
        )
        val enc = encodeJoinerInfo(info, key)
        val dec = decodeJoinerInfo(enc, key, nowEpochSeconds = now)!!
        assertEquals(info, dec)
    }

    @Test fun `joiner info with no device name still round-trips`() {
        val info = JoinerEnrollInfo(timestamp = now, wgPubkeyB64 = pubkeyB64)
        val dec = decodeJoinerInfo(encodeJoinerInfo(info, key), key, now)!!
        assertEquals(info, dec)
        assertNull(dec.deviceName)
    }

    @Test fun `joiner info decode rejects wrong key`() {
        val info = JoinerEnrollInfo(timestamp = now, wgPubkeyB64 = pubkeyB64)
        val enc = encodeJoinerInfo(info, key)
        val wrongKey = ByteArray(32) { 9 }
        assertNull(decodeJoinerInfo(enc, wrongKey, now))
    }

    @Test fun `joiner info decode rejects stale timestamp`() {
        val info = JoinerEnrollInfo(timestamp = now, wgPubkeyB64 = pubkeyB64)
        val enc = encodeJoinerInfo(info, key)
        // Freshness window default is 90 s; 200 s out-of-window.
        assertNull(decodeJoinerInfo(enc, key, nowEpochSeconds = now + 200))
    }

    @Test fun `joiner info decode rejects malformed pubkey`() {
        val info = JoinerEnrollInfo(timestamp = now, wgPubkeyB64 = "not!base64!")
        val enc = encodeJoinerInfo(info, key)
        assertNull(decodeJoinerInfo(enc, key, now))
    }

    @Test fun `joiner info decode rejects junk ciphertext`() {
        val junk = ByteArray(80) { 99 }
        assertNull(decodeJoinerInfo(junk, key, now))
    }

    @Test fun `joiner info encode rejects too-short shared key`() {
        val info = JoinerEnrollInfo(timestamp = now, wgPubkeyB64 = pubkeyB64)
        assertThrows(IllegalArgumentException::class.java) {
            encodeJoinerInfo(info, ByteArray(16))
        }
    }

    // ─── Host round-trip ─────────────────────────────────────────

    @Test fun `host info round-trips with all fields`() {
        val info = HostEnrollInfo(
            timestamp = now,
            wgPubkeyB64 = pubkeyB64,
            wgEndpoint = "203.0.113.5:51820",
            assignedAddress = "10.99.0.2/32",
            allowedIps = "10.99.0.0/24",
            brokerWss = "wss://example.com/peerjs",
            brokerKey = "peerjs",
            saltB64 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
            dns = "1.1.1.1",
            mtu = 1420,
            keepalive = 25,
            hostName = "phone-A",
        )
        val dec = decodeHostInfo(encodeHostInfo(info, key), key, now)!!
        assertEquals(info, dec)
    }

    @Test fun `host info round-trips with minimal fields`() {
        val info = HostEnrollInfo(
            timestamp = now,
            wgPubkeyB64 = pubkeyB64,
            wgEndpoint = "1.2.3.4:51820",
            assignedAddress = "10.99.0.2/32",
            allowedIps = "10.99.0.0/24",
        )
        val dec = decodeHostInfo(encodeHostInfo(info, key), key, now)!!
        assertEquals(info, dec)
        assertNull(dec.dns)
        assertNull(dec.mtu)
    }

    @Test fun `host info decode rejects wrong key`() {
        val info = HostEnrollInfo(
            timestamp = now,
            wgPubkeyB64 = pubkeyB64,
            wgEndpoint = "1.2.3.4:51820",
            assignedAddress = "10.99.0.2/32",
            allowedIps = "10.99.0.0/24",
        )
        val enc = encodeHostInfo(info, key)
        assertNull(decodeHostInfo(enc, ByteArray(32) { 0xff.toByte() }, now))
    }

    @Test fun `host info decode rejects stale timestamp`() {
        val info = HostEnrollInfo(
            timestamp = now,
            wgPubkeyB64 = pubkeyB64,
            wgEndpoint = "1.2.3.4:51820",
            assignedAddress = "10.99.0.2/32",
            allowedIps = "10.99.0.0/24",
        )
        val enc = encodeHostInfo(info, key)
        assertNull(decodeHostInfo(enc, key, nowEpochSeconds = now - 1000))
    }
}
