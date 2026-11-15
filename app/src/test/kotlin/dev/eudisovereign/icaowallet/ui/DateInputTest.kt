package dev.eudisovereign.icaowallet.ui

import dev.eudisovereign.icaowallet.crypto.Codec
import dev.eudisovereign.icaowallet.nfc.AccessKey
import dev.eudisovereign.icaowallet.nfc.AccessKeyRules
import java.time.LocalDate
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class DateInputTest {

    private fun problemOf(digits: String, notAfter: LocalDate? = null): DateProblem? =
        (DateInput.parse(digits, notAfter) as? DateParse.Invalid)?.problem

    @Test
    fun convertsDdMmYyyyToYymmdd() {
        assertEquals("690806", DateInput.toYymmdd("06081969"))
        assertEquals("940623", DateInput.toYymmdd("23061994"))
        assertEquals("000229", DateInput.toYymmdd("29022000"))
        assertEquals("310101", DateInput.toYymmdd("01012031"))
    }

    @Test
    fun convertedDatesSatisfyTheAccessKeyRules() {
        listOf("06081969", "29021996", "31122099", "01011900").forEach { digits ->
            assertNull(AccessKeyRules.dateProblem("Date", DateInput.toYymmdd(digits)!!))
        }
    }

    // ICAO 9303-11 Appendix D, BAC worked example: date of birth 1969-08-06, date of expiry 1994-06-23
    @Test
    fun convertedDatesDeriveTheIcaoWorkedExampleKey() {
        val key = AccessKey.Mrz("L898902C", DateInput.toYymmdd("06081969")!!, DateInput.toYymmdd("23061994")!!)
        assertEquals("239ab9cb282daf66231dc5a4df6bfbae", Codec.hex(key.bacKey().key))
    }

    @Test
    fun incompleteInputIsNotAnError() {
        assertEquals(DateProblem.INCOMPLETE, problemOf(""))
        assertEquals(DateProblem.INCOMPLETE, problemOf("0608196"))
        assertEquals(DateProblem.INCOMPLETE, problemOf("06/08/1969"))
        assertNull(DateInput.toYymmdd("0608"))
    }

    @Test
    fun rejectsDatesThatDoNotExist() {
        assertEquals(DateProblem.NOT_A_DATE, problemOf("31042020"))
        assertEquals(DateProblem.NOT_A_DATE, problemOf("30022020"))
        assertEquals(DateProblem.NOT_A_DATE, problemOf("29021900"))
        assertEquals(DateProblem.NOT_A_DATE, problemOf("29022021"))
        assertEquals(DateProblem.NOT_A_DATE, problemOf("00012020"))
        assertEquals(DateProblem.NOT_A_DATE, problemOf("01132020"))
        assertEquals(DateProblem.NOT_A_DATE, problemOf("01002020"))
        assertNull(DateInput.toYymmdd("31042020"))
    }

    @Test
    fun rejectsYearsOutsideTheMrzRange() {
        assertEquals(DateProblem.OUT_OF_RANGE, problemOf("31121899"))
        assertEquals(DateProblem.OUT_OF_RANGE, problemOf("01012100"))
        assertEquals(DateProblem.OUT_OF_RANGE, problemOf("01010000"))
    }

    @Test
    fun rejectsDatesAfterTheLimit() {
        val today = LocalDate.of(2026, 11, 15)
        assertEquals(DateProblem.IN_FUTURE, problemOf("16112026", today))
        assertNull(problemOf("15112026", today))
        assertNull(DateInput.toYymmdd("16112026", today))
        assertEquals("261116", DateInput.toYymmdd("16112026"))
    }

    @Test
    fun filterKeepsEightDigits() {
        assertEquals("06081969", DateInput.filter("06/08/1969"))
        assertEquals("12345678", DateInput.filter("1234567890"))
        assertEquals("", DateInput.filter("ab-/"))
    }

    @Test
    fun displayInsertsSlashesOnlyBetweenTypedDigits() {
        assertEquals("", DateInput.display(""))
        assertEquals("06", DateInput.display("06"))
        assertEquals("06/0", DateInput.display("060"))
        assertEquals("06/08", DateInput.display("0608"))
        assertEquals("06/08/1", DateInput.display("06081"))
        assertEquals("06/08/1969", DateInput.display("06081969"))
    }

    @Test
    fun cursorOffsetsStayWithinBoundsAndRoundTrip() {
        for (length in 0..DateInput.DIGITS) {
            val shown = DateInput.display("1".repeat(length)).length
            for (offset in 0..length) {
                val displayed = DateInput.displayOffset(offset, length)
                assertTrue(displayed in 0..shown)
                assertEquals(offset, DateInput.originalOffset(displayed, length))
            }
            for (offset in 0..shown) {
                assertTrue(DateInput.originalOffset(offset, length) in 0..length)
            }
        }
    }
}
