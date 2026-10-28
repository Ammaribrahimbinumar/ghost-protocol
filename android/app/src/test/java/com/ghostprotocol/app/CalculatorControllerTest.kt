package com.ghostprotocol.app

import com.ghostprotocol.app.calc.CalculatorController
import com.ghostprotocol.app.security.UnlockVerifier
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class CalculatorControllerTest {
    private val secret = "2468"
    private val store = MemoryStore()
    private val clock = FakeClock()
    private val verifier = UnlockVerifier(store, clock, iterations = 1000).also { it.configure(secret.toCharArray()) }
    private val calc = CalculatorController(verifier)

    private fun type(s: String) = s.forEach { calc.press(it.toString()) }

    @Test fun ordinaryCalculationStillWorks() = runTest {
        type("5×5")
        assertFalse(calc.submit())
        assertEquals("25", calc.display.value)
    }

    @Test fun secretOpensAndWipesInput() = runTest {
        type(secret)
        assertTrue(calc.submit())
        assertEquals("", calc.display.value)
        assertTrue(calc.isInputWiped())
    }

    @Test fun secretWithOperatorIsJustArithmetic() = runTest {
        type("2468+1")
        assertFalse(calc.submit())
        assertEquals("2469", calc.display.value)
    }

    @Test fun wrongCodeLooksLikeAnOrdinaryNumber() = runTest {
        type("1357")
        assertFalse(calc.submit())
        assertEquals("1357", calc.display.value)
    }

    @Test fun throttledCorrectCodeLooksIdenticalToAWrongOne() = runTest {
        repeat(5) { type("1111"); calc.submit(); calc.press("C") }
        type(secret)
        assertFalse(calc.submit()) // locked out: must NOT unlock
        assertEquals(secret, calc.display.value) // and shows exactly what a wrong code shows
    }

    @Test fun lockWipesEverything() = runTest {
        type("987654")
        calc.lock()
        assertEquals("", calc.display.value)
        assertTrue(calc.isInputWiped())
    }

    @Test fun errorsShowErrorAndKeepInput() = runTest {
        type("1÷0")
        assertFalse(calc.submit())
        assertEquals("Error", calc.display.value)
    }

    @Test fun disallowedCharactersAreIgnored() = runTest {
        calc.press("a"); calc.press("$"); calc.press("7")
        assertEquals("7", calc.display.value)
    }

    @Test fun decoyAndDuressOutcomesAreReportedAndWipeInput() = runTest {
        verifier.configureDecoy("1357".toCharArray()); verifier.configureDuress("9753".toCharArray())
        type("1357"); assertEquals(com.ghostprotocol.app.calc.UnlockOutcome.DECOY, calc.submitOutcome()); assertTrue(calc.isInputWiped())
        type("9753"); assertEquals(com.ghostprotocol.app.calc.UnlockOutcome.DURESS, calc.submitOutcome()); assertTrue(calc.isInputWiped())
        type("2468"); assertEquals(com.ghostprotocol.app.calc.UnlockOutcome.REAL, calc.submitOutcome())
        type("12+1"); assertEquals(com.ghostprotocol.app.calc.UnlockOutcome.NONE, calc.submitOutcome()); assertEquals("13", calc.display.value)
        type("1357"); assertFalse("submit() stays true only for the main code", calc.submit())
    }
}
