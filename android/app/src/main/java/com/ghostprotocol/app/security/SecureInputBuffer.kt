package com.ghostprotocol.app.security

/**
 * Fixed-capacity character buffer for sensitive input (calculator digits that may be the
 * unlock secret, PIN entry, message composition).
 *
 * Why not a String: a String is immutable and cannot be overwritten, so its contents linger
 * until garbage collection. This buffer is a CharArray that clear() overwrites with zeros.
 *
 * Honest limit: Compose's Text needs a String to draw, so [asString] creates a transient copy
 * that this class cannot wipe. The JVM also gives no guarantee about stray copies. This reduces
 * exposure; it does not eliminate it.
 */
class SecureInputBuffer(private val capacity: Int) {
    private val buf = CharArray(capacity)

    var length: Int = 0
        private set

    fun append(c: Char): Boolean {
        if (length >= capacity) return false
        buf[length++] = c
        return true
    }

    fun appendAll(text: CharSequence): Boolean {
        if (length + text.length > capacity) return false
        for (ch in text) buf[length++] = ch
        return true
    }

    fun deleteLast() {
        if (length > 0) {
            length--
            buf[length] = '\u0000'
        }
    }

    fun clear() {
        buf.fill('\u0000')
        length = 0
    }

    fun isAllDigits(): Boolean {
        if (length == 0) return false
        for (k in 0 until length) if (buf[k] !in '0'..'9') return false
        return true
    }

    /** Copy of the current contents. The caller owns it and must zero it when done. */
    fun snapshot(): CharArray = buf.copyOf(length)

    /** Transient String for drawing. See class comment for the limitation. */
    fun asString(): String = String(buf, 0, length)

    /** True when every slot in the backing array is zero (used by tests). */
    fun isFullyZeroed(): Boolean = buf.all { it == '\u0000' }

    // Never expose contents through logging or crash reports.
    override fun toString(): String = "SecureInputBuffer(length=$length)"
}
