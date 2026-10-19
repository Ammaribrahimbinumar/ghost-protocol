package com.ghostprotocol.app

import com.ghostprotocol.app.calc.CalcException
import com.ghostprotocol.app.calc.Evaluator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class EvaluatorTest {
    private fun eval(s: String) = Evaluator.evaluate(s)

    @Test fun precedence() = assertEquals("7", eval("1+2*3"))
    @Test fun parentheses() = assertEquals("9", eval("(1+2)*3"))
    @Test fun decimalsAreExact() = assertEquals("0.3", eval("0.1+0.2"))
    @Test fun unicodeOperators() = assertEquals("2.5", eval("10÷4"))
    @Test fun unicodeMinus() = assertEquals("1", eval("3−2"))
    @Test fun percent() = assertEquals("0.5", eval("50%"))
    @Test fun percentOfValue() = assertEquals("20", eval("200×10%"))
    @Test fun unaryMinus() = assertEquals("-3", eval("-5+2"))
    @Test fun doubleNegative() = assertEquals("5", eval("2--3"))
    @Test fun repeatingDecimalIsRounded() = assertEquals("0.333333333333", eval("1/3"))
    @Test fun nestedWithinLimit() = assertEquals("1", eval("((((1))))"))

    @Test fun divideByZero() {
        assertThrows(CalcException::class.java) { eval("1/0") }
    }

    @Test fun malformedInputsThrowCalcExceptionOnly() {
        for (bad in listOf("", "(1+2", "1..2", ".", "1+", "abc", "1e5", "()", "1+*2", ")")) {
            assertThrows("input: $bad", CalcException::class.java) { eval(bad) }
        }
    }

    @Test fun excessiveNestingIsRejectedNotCrashed() {
        val deep = "(".repeat(100) + "1" + ")".repeat(100)
        assertThrows(CalcException::class.java) { eval(deep) }
    }

    @Test fun overlongInputIsRejected() {
        assertThrows(CalcException::class.java) { eval("1+".repeat(150) + "1") }
    }
}
