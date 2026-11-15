package dev.eudisovereign.icaowallet.ui

import dev.eudisovereign.icaowallet.report.MrzFieldId

object Masking {
    private const val BULLET = "•"

    /** Fixed length, so masked text reveals neither the content nor the length of the value. */
    val HIDDEN: String = BULLET.repeat(8)

    private val PREFIX: String = BULLET.repeat(6)

    private val NOT_PERSONAL = setOf(MrzFieldId.DOCUMENT_CODE, MrzFieldId.ISSUING_STATE, MrzFieldId.COMPOSITE_CHECK)

    fun mask(value: String, revealed: Boolean): String = if (revealed) value else HIDDEN

    /** Keeps the last [visible] characters behind a fixed prefix; a value no longer than [visible] is fully hidden. */
    fun keepLast(value: String, visible: Int): String {
        require(visible >= 0) { "visible must not be negative" }
        return if (value.length <= visible) HIDDEN else PREFIX + value.takeLast(visible)
    }

    /** MRZ lines are replaced line by line, keeping only the number of lines visible. */
    fun maskLines(lines: List<String>, revealed: Boolean): String =
        if (revealed) lines.joinToString("\n") else lines.joinToString("\n") { HIDDEN }

    fun isPersonal(id: MrzFieldId): Boolean = id !in NOT_PERSONAL
}
