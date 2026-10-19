package com.ghostprotocol.app.calc

import java.math.BigDecimal
import java.math.MathContext
import java.math.RoundingMode

class CalcException(message: String) : Exception(message)

/**
 * Arithmetic evaluator for the calculator front-end.
 *
 * Grammar:
 *   expr    := term (('+' | '-') term)*
 *   term    := unary (('*' | '/') unary)*
 *   unary   := ('-' | '+') unary | postfix
 *   postfix := primary '%'*          // '%' divides by 100
 *   primary := number | '(' expr ')'
 *
 * Uses BigDecimal so 0.1 + 0.2 displays as 0.3.
 */
object Evaluator {
    private const val MAX_INPUT = 200
    private const val MAX_DEPTH = 40
    private val MC = MathContext(20, RoundingMode.HALF_EVEN)
    private val DISPLAY_MC = MathContext(12, RoundingMode.HALF_EVEN)
    private val HUNDRED = BigDecimal(100)

    fun evaluate(input: String): String {
        if (input.length > MAX_INPUT) throw CalcException("input too long")
        val normalised = input.replace('×', '*').replace('÷', '/').replace('−', '-').filterNot { it.isWhitespace() }
        return format(Parser(normalised).parseAll())
    }

    fun format(v: BigDecimal): String {
        val r = v.round(DISPLAY_MC).stripTrailingZeros()
        return r.toPlainString()
    }

    private class Parser(private val s: String) {
        private var i = 0
        private var depth = 0

        fun parseAll(): BigDecimal {
            if (s.isEmpty()) throw CalcException("empty")
            val v = expr()
            if (i != s.length) throw CalcException("unexpected '${s[i]}'")
            return v
        }

        private fun peek(): Char? = if (i < s.length) s[i] else null

        private fun expr(): BigDecimal {
            var v = term()
            while (true) {
                val op = peek()
                if (op != '+' && op != '-') return v
                i++
                val r = term()
                v = if (op == '+') v.add(r, MC) else v.subtract(r, MC)
            }
        }

        private fun term(): BigDecimal {
            var v = unary()
            while (true) {
                val op = peek()
                if (op != '*' && op != '/') return v
                i++
                val r = unary()
                v = if (op == '*') {
                    v.multiply(r, MC)
                } else {
                    if (r.signum() == 0) throw CalcException("divide by zero")
                    v.divide(r, MC)
                }
            }
        }

        private fun unary(): BigDecimal {
            if (++depth > MAX_DEPTH) throw CalcException("too deeply nested")
            try {
                return when (peek()) {
                    '-' -> { i++; unary().negate() }
                    '+' -> { i++; unary() }
                    else -> postfix()
                }
            } finally {
                depth--
            }
        }

        private fun postfix(): BigDecimal {
            var v = primary()
            while (peek() == '%') {
                i++
                v = v.divide(HUNDRED, MC)
            }
            return v
        }

        private fun primary(): BigDecimal {
            val c = peek() ?: throw CalcException("unexpected end")
            if (c == '(') {
                i++
                if (++depth > MAX_DEPTH) throw CalcException("too deeply nested")
                val v = expr()
                depth--
                if (peek() != ')') throw CalcException("missing )")
                i++
                return v
            }
            val start = i
            var dots = 0
            while (i < s.length && (s[i].isDigit() || s[i] == '.')) {
                if (s[i] == '.') dots++
                i++
            }
            if (i == start || dots > 1) throw CalcException("bad number")
            val token = s.substring(start, i)
            if (token == ".") throw CalcException("bad number")
            return try {
                BigDecimal(token)
            } catch (e: NumberFormatException) {
                throw CalcException("bad number")
            }
        }
    }
}
