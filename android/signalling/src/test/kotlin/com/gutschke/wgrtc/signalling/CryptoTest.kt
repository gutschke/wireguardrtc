package com.gutschke.wgrtc.signalling

import com.goterl.lazysodium.LazySodiumJava
import com.goterl.lazysodium.SodiumJava
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import java.util.Base64

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class CryptoTest {

    @BeforeAll fun installJvmSodium() {
        // Swap the LazySodium impl for the JVM variant. See
        // Sodium.setForTest in Crypto.kt for rationale.
        Sodium.setForTest(LazySodiumJava(SodiumJava()))
    }

    @AfterAll fun restoreSodium() {
        Sodium.setForTest(null)
    }

    // ─── Reference vectors generated from the Python daemon's nacl
    // bindings. See tests/22-style scripts in github/ to regenerate.
    private fun hex(s: String): ByteArray = s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    private val privA = hex("01".repeat(32))
    private val pubA = hex("a4e09292b651c278b9772c569f5fa9bb13d906b46ab68c9df9dc2b4409f8a209")
    private val privB = hex("02".repeat(32))
    private val pubB = hex("ce8d3ad1ccb633ec7b70c17814a5c76ecd029685050d344745ba05870e587d59")
    private val sharedAb = hex("2ed76ab549b1e73c031eb49c9448f0798aea81b698279a0c3dc3e49fbfc4b953")
    private val blakeHelloSig = hex("58ff0b1bd27f33147c185bfe77e14dc84620b2b2825a5f873015ba6fe69e8b8e")
    private val sigKeyAB = hex("634d6d91c2d76c3017ee3384933c1d3c42503e96704492a5dc59ae021e42dad1")
    private val token = hex("aa".repeat(32))
    private val enrollKeyAB = hex("854f715a282670c645a7b378a2ed4b8011d48b4cf98745698457287d7f07a4e8")
    private val salt = hex("cc".repeat(32))
    private val pubAb64 = "pOCSkrZRwni5dyxWn1+puxPZBrRqtoyd+dwrRAn4ogk="
    private val expectedRoutingId = "a962408955ebb3b06afc5f58acec12367f692ee2f16f02bc6acaf5aee325c7cf"

    @Test fun `x25519 produces the daemon's shared secret`() {
        // Both directions of the ECDH yield the same secret.
        assertArrayEquals(sharedAb, x25519(privA, pubB))
        assertArrayEquals(sharedAb, x25519(privB, pubA))
    }

    @Test fun `x25519 rejects wrong-size keys`() {
        assertThrows(IllegalArgumentException::class.java) {
            x25519(ByteArray(31), pubB)
        }
        assertThrows(IllegalArgumentException::class.java) {
            x25519(privA, ByteArray(33))
        }
    }

    @Test fun `blake2b32 with explicit key matches PyNaCl`() {
        // The daemon passes the literal label bytes (19 chars), not a
        // zero-padded 32-byte key — Python slicing `LABEL[:32]` is a
        // no-op when len < 32. Match that exactly so the byte-identity
        // assertion against the reference vector holds.
        val key = "wg-peerjs/v1/sigbox".toByteArray(Charsets.UTF_8)
        assertEquals(19, key.size)
        val out = blake2b32("hello".toByteArray(), key)
        assertArrayEquals(blakeHelloSig, out)
    }

    @Test fun `deriveSigboxKey matches the daemon`() {
        assertArrayEquals(sigKeyAB, deriveSigboxKey(privA, pubB))
    }

    @Test fun `deriveEnrollKey matches the daemon`() {
        assertArrayEquals(enrollKeyAB, deriveEnrollKey(privA, pubB, token))
    }

    @Test fun `domain-separation labels are wire-format constants`() {
        // If anyone ever "fixes" these labels the daemon stops talking
        // to us. Lock the bytes in.
        assertArrayEquals(
            "wg-peerjs/v1/sigbox".toByteArray(Charsets.UTF_8),
            CryptoLabels.SIGBOX,
        )
        assertArrayEquals(
            "wg-peerjs/v1/enroll".toByteArray(Charsets.UTF_8),
            CryptoLabels.ENROLL,
        )
    }

    @Test fun `secretbox round-trip`() {
        val key = ByteArray(32) { 0x33.toByte() }
        val plaintext = "the quick brown fox".toByteArray()
        val ct = secretboxEncrypt(plaintext, key)
        // [nonce(24) || boxed]. Different nonce each call.
        assertEquals(24 + plaintext.size + 16, ct.size)
        val pt = secretboxDecrypt(ct, key)
        assertArrayEquals(plaintext, pt)
    }

    @Test fun `secretbox returns null on auth-tag mismatch`() {
        val key = ByteArray(32) { 0x33.toByte() }
        val ct = secretboxEncrypt("hello".toByteArray(), key)
        ct[ct.size - 1] = (ct[ct.size - 1].toInt() xor 1).toByte()
        assertNull(secretboxDecrypt(ct, key))
    }

    @Test fun `secretbox returns null with wrong key`() {
        val key1 = ByteArray(32) { 0x33.toByte() }
        val key2 = ByteArray(32) { 0x44.toByte() }
        val ct = secretboxEncrypt("hello".toByteArray(), key1)
        assertNull(secretboxDecrypt(ct, key2))
    }

    @Test fun `routingId matches the daemon's hex SHA256`() {
        // Confirm we got back the same pubkey as the python reference
        // (round-trip via Base64 is deterministic only when both sides
        // use the SAME alphabet; daemon uses the standard alphabet).
        assertEquals(pubAb64, Base64.getEncoder().encodeToString(pubA))
        assertEquals(expectedRoutingId, routingId(pubAb64, salt))
    }

    @Test fun `generateKeyPair yields a valid Curve25519 pair`() {
        val kp = generateKeyPair()
        // The pubkey is derivable from the priv via scalar-mult-base.
        // We exercise that indirectly: ECDH against a known peer is
        // commutative iff both keys are valid.
        val peer = generateKeyPair()
        val s1 = x25519(kp.privateKey, peer.publicKey)
        val s2 = x25519(peer.privateKey, kp.publicKey)
        assertArrayEquals(s1, s2)
    }
}
