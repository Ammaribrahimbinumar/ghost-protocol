package com.ghostprotocol.app.calc

import com.ghostprotocol.app.security.SecureInputBuffer
import com.ghostprotocol.app.security.StoreCorruptedException
import com.ghostprotocol.app.security.UnlockVerifier
import com.ghostprotocol.app.security.VerifyResult
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext

/**
 * Drives the calculator screen. It works as an ordinary calculator for every input except one
 * that matches the configured secret when "=" is pressed.
 *
 * Design points:
 * - A wrong guess, a throttled guess, and a plain calculation all look identical to the user:
 *   the digits are evaluated as a number. Nothing reveals that an unlock secret exists.
 * - Input lives in a [SecureInputBuffer] that is zeroed on unlock, on lock and on clear.
 * - Nothing here logs input.
 */
class CalculatorController(private val verifier: UnlockVerifier) {
    private val input = SecureInputBuffer(MAX_INPUT)
    private val _display = MutableStateFlow("")
    val display: StateFlow<String> = _display.asStateFlow()

    companion object {
        const val MAX_INPUT = 100
        private const val ALLOWED = "0123456789+-×÷−*/().%"
    }

    fun press(key: String) {
        when (key) {
            "C" -> input.clear()
            "⌫" -> input.deleteLast()
            else -> if (key.length == 1 && key[0] in ALLOWED) input.append(key[0])
        }
        publish()
    }

    /** @return true if the secret matched and the messenger should open. */
    suspend fun submit(): Boolean {
        if (input.length in UnlockVerifier.MIN_LEN..UnlockVerifier.MAX_LEN && input.isAllDigits()) {
            val candidate = input.snapshot()
            val result = try {
                withContext(Dispatchers.Default) { verifier.verify(candidate) }
            } catch (e: StoreCorruptedException) {
                VerifyResult.REJECTED // behave like a calculator; the UI layer reports corruption elsewhere
            } finally {
                candidate.fill('\u0000')
            }
            if (result == VerifyResult.ACCEPTED) {
                lock()
                return true
            }
        }
        val shown = try {
            Evaluator.evaluate(input.asString())
        } catch (e: CalcException) {
            "Error"
        }
        if (shown != "Error") {
            input.clear()
            input.appendAll(shown)
        }
        _display.value = shown
        return false
    }

    /** Wipes input and display. Called on unlock, on leaving the app, and on process stop. */
    fun lock() {
        input.clear()
        _display.value = ""
    }

    internal fun isInputWiped(): Boolean = input.isFullyZeroed()

    private fun publish() {
        _display.value = input.asString()
    }
}
