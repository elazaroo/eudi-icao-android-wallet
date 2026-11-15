package dev.eudisovereign.icaowallet.ui

import dev.eudisovereign.icaowallet.report.MrzFieldId
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class MaskingTest {

    @Test
    fun maskedValuesHaveOneFixedLength() {
        val short = Masking.mask("M", revealed = false)
        val long = Masking.mask("L898902C3", revealed = false)
        val empty = Masking.mask("", revealed = false)
        assertEquals(Masking.HIDDEN, short)
        assertEquals(short, long)
        assertEquals(short, empty)
        assertTrue(Masking.HIDDEN.all { it == '•' })
    }

    @Test
    fun maskedValuesRevealNoCharacter() {
        val value = "ERIKSSON"
        assertTrue(Masking.mask(value, revealed = false).none { it in value })
    }

    @Test
    fun revealedValuesAreUnchanged() {
        assertEquals("L898902C3", Masking.mask("L898902C3", revealed = true))
        assertEquals("", Masking.mask("", revealed = true))
    }

    @Test
    fun keepLastShowsOnlyTheTailBehindAFixedPrefix() {
        assertEquals("••••••902", Masking.keepLast("L898902", 3))
        assertEquals(Masking.keepLast("AB1234", 3).length, Masking.keepLast("AB12345678", 3).length)
        assertFalse(Masking.keepLast("L898902C3", 3).contains("L898"))
    }

    @Test
    fun keepLastHidesShortValuesCompletely() {
        assertEquals(Masking.HIDDEN, Masking.keepLast("C3", 3))
        assertEquals(Masking.HIDDEN, Masking.keepLast("902", 3))
        assertEquals(Masking.HIDDEN, Masking.keepLast("", 3))
        assertThrows(IllegalArgumentException::class.java) { Masking.keepLast("123", -1) }
    }

    @Test
    fun mrzLinesAreMaskedLineByLine() {
        val lines = listOf("I<UTOD231458907<<<<<<<<<<<<<<<", "7408122F1204159UTO<<<<<<<<<<<6", "ERIKSSON<<ANNA<MARIA<<<<<<<<<<")
        val masked = Masking.maskLines(lines, revealed = false)
        assertEquals(List(3) { Masking.HIDDEN }.joinToString("\n"), masked)
        assertEquals(lines.joinToString("\n"), Masking.maskLines(lines, revealed = true))
    }

    @Test
    fun onlyHolderDataIsPersonal() {
        assertTrue(Masking.isPersonal(MrzFieldId.DOCUMENT_NUMBER))
        assertTrue(Masking.isPersonal(MrzFieldId.PERSONAL_NUMBER))
        assertTrue(Masking.isPersonal(MrzFieldId.OPTIONAL_DATA_1))
        assertTrue(Masking.isPersonal(MrzFieldId.DATE_OF_BIRTH))
        assertTrue(Masking.isPersonal(MrzFieldId.PRIMARY_IDENTIFIER))
        assertTrue(Masking.isPersonal(MrzFieldId.SECONDARY_IDENTIFIER))
        assertFalse(Masking.isPersonal(MrzFieldId.DOCUMENT_CODE))
        assertFalse(Masking.isPersonal(MrzFieldId.ISSUING_STATE))
        assertFalse(Masking.isPersonal(MrzFieldId.COMPOSITE_CHECK))
    }
}
