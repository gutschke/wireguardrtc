package com.gutschke.wgrtc.data

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class VpnServiceFdProtectorTest {

    @Test
    fun `forwards fd to lambda and returns its boolean`() {
        val received = mutableListOf<Int>()
        val protector = VpnServiceFdProtector { fd -> received += fd; true }
        assertTrue(protector.protect(42))
        assertEquals(listOf(42), received)
    }

    @Test
    fun `returns false when lambda denies`() {
        val protector = VpnServiceFdProtector { false }
        assertFalse(protector.protect(99))
    }

    @Test
    fun `each call routes through the lambda`() {
        val calls = mutableListOf<Int>()
        val protector = VpnServiceFdProtector { fd -> calls += fd; fd > 0 }
        assertFalse(protector.protect(-1))
        assertTrue(protector.protect(7))
        assertTrue(protector.protect(8))
        assertEquals(listOf(-1, 7, 8), calls)
    }
}
