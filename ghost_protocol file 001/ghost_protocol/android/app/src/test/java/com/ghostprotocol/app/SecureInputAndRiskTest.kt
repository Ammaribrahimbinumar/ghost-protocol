package com.ghostprotocol.app

import com.ghostprotocol.app.security.AccessibilityServiceSummary
import com.ghostprotocol.app.security.RiskCheck
import com.ghostprotocol.app.security.RiskInputs
import com.ghostprotocol.app.security.RiskPolicy
import com.ghostprotocol.app.security.SecureInputBuffer
import com.ghostprotocol.app.security.Severity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SecureInputBufferTest {
    @Test fun appendAndDelete() {
        val b = SecureInputBuffer(4)
        assertTrue(b.append('1')); assertTrue(b.append('2'))
        assertEquals("12", b.asString())
        b.deleteLast()
        assertEquals("1", b.asString())
    }

    @Test fun capacityIsEnforced() {
        val b = SecureInputBuffer(2)
        assertTrue(b.append('a')); assertTrue(b.append('b'))
        assertFalse(b.append('c'))
        assertFalse(b.appendAll("xyz"))
        assertEquals("ab", b.asString())
    }

    @Test fun clearZeroesBackingArray() {
        val b = SecureInputBuffer(8)
        b.appendAll("secret12")
        assertFalse(b.isFullyZeroed())
        b.clear()
        assertTrue(b.isFullyZeroed())
        assertEquals(0, b.length)
    }

    @Test fun deleteLastZeroesTheSlot() {
        val b = SecureInputBuffer(8)
        b.appendAll("ab")
        b.deleteLast(); b.deleteLast()
        assertTrue(b.isFullyZeroed())
    }

    @Test fun toStringNeverRevealsContents() {
        val b = SecureInputBuffer(8)
        b.appendAll("hunter2")
        assertFalse(b.toString().contains("hunter2"))
    }

    @Test fun isAllDigits() {
        val b = SecureInputBuffer(8)
        assertFalse(b.isAllDigits()) // empty
        b.appendAll("1234"); assertTrue(b.isAllDigits())
        b.append('+'); assertFalse(b.isAllDigits())
    }
}

class RiskCheckTest {
    private val clean = RiskInputs(emptyList(), adbEnabled = false, developerOptionsEnabled = false)

    @Test fun cleanDeviceHasNoFindings() = assertTrue(RiskCheck.evaluate(clean).isEmpty())

    @Test fun screenReadingServiceIsHigh() {
        val f = RiskCheck.evaluate(clean.copy(accessibilityServices = listOf(AccessibilityServiceSummary("Foo", true))))
        assertEquals(Severity.HIGH, f.single().severity)
    }

    @Test fun nonReadingServiceIsWarn() {
        val f = RiskCheck.evaluate(clean.copy(accessibilityServices = listOf(AccessibilityServiceSummary("Foo", false))))
        assertEquals(Severity.WARN, f.single().severity)
    }

    @Test fun adbAndDeveloperOptions() {
        val f = RiskCheck.evaluate(clean.copy(adbEnabled = true, developerOptionsEnabled = true))
        assertEquals(setOf("adb", "devopts"), f.map { it.id }.toSet())
    }

    @Test fun policyDecidesWhetherHighFindingsBlock() {
        val high = RiskCheck.evaluate(clean.copy(accessibilityServices = listOf(AccessibilityServiceSummary("Foo", true))))
        assertTrue(RiskCheck.blocks(high, RiskPolicy.BLOCK_ON_HIGH))
        assertFalse(RiskCheck.blocks(high, RiskPolicy.WARN_ONLY))
        assertFalse(RiskCheck.blocks(emptyList(), RiskPolicy.BLOCK_ON_HIGH))
    }
}
