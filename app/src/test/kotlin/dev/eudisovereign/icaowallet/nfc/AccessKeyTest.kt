package dev.eudisovereign.icaowallet.nfc

import dev.eudisovereign.icaowallet.crypto.Codec
import dev.eudisovereign.icaowallet.ui.AccessKeyForm
import dev.eudisovereign.icaowallet.ui.AccessKeyMode
import org.jmrtd.PassportService
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class AccessKeyTest {

    // ICAO 9303-11 Appendix D, BAC worked example: document number L898902C<, check digits 3, 1 and 6
    private val icaoMrzInformation = "L898902C<369080619406236"

    @Test
    fun inputFiltersNormaliseWhatTheUserTypes() {
        assertEquals("123456", AccessKeyRules.filterCan("12 34-567"))
        assertEquals("AB12C<D", AccessKeyRules.filterDocumentNumber("ab 12-c<d"))
        assertEquals("ABCDEFGHI", AccessKeyRules.filterDocumentNumber("abcdefghijk"))
        assertEquals("690806", AccessKeyRules.filterDate("69/08/061"))
    }

    @Test
    fun canMustBeSixDigits() {
        assertNull(AccessKeyRules.canProblem("012345"))
        assertNotNull(AccessKeyRules.canProblem("12345"))
        assertNotNull(AccessKeyRules.canProblem("1234567"))
        assertNotNull(AccessKeyRules.canProblem("12345a"))
        assertThrows(IllegalArgumentException::class.java) { AccessKey.Can("12345") }
    }

    @Test
    fun documentNumberRules() {
        assertNull(AccessKeyRules.documentNumberProblem("L898902C"))
        assertNull(AccessKeyRules.documentNumberProblem("L898902C<"))
        assertNull(AccessKeyRules.documentNumberProblem("1"))
        assertNotNull(AccessKeyRules.documentNumberProblem(""))
        assertNotNull(AccessKeyRules.documentNumberProblem("<L898902"))
        assertNotNull(AccessKeyRules.documentNumberProblem("l898902c"))
        assertNotNull(AccessKeyRules.documentNumberProblem("L898902C12"))
    }

    @Test
    fun datesMustBeSixDigitCalendarDates() {
        assertNull(AccessKeyRules.dateProblem("Date", "690806"))
        assertNull(AccessKeyRules.dateProblem("Date", "000229"))
        assertNull(AccessKeyRules.dateProblem("Date", "961231"))
        assertTrue(AccessKeyRules.dateProblem("Date", "6908")!!.contains("6 digits"))
        assertTrue(AccessKeyRules.dateProblem("Date", "69a806")!!.contains("6 digits"))
        assertTrue(AccessKeyRules.dateProblem("Date", "691301")!!.contains("calendar date"))
        assertTrue(AccessKeyRules.dateProblem("Date", "690230")!!.contains("calendar date"))
        assertTrue(AccessKeyRules.dateProblem("Date", "010229")!!.contains("calendar date"))
        assertTrue(AccessKeyRules.dateProblem("Date", "690800")!!.contains("calendar date"))
    }

    @Test
    fun mrzKeyRejectsInvalidInput() {
        assertEquals(3, AccessKeyRules.mrzProblems("", "6908", "941323").size)
        assertThrows(IllegalArgumentException::class.java) { AccessKey.Mrz("L898902C", "690806", "940631") }
    }

    @Test
    fun bacKeySeedMatchesTheIcaoWorkedExample() {
        val key = AccessKey.Mrz("L898902C", "690806", "940623")
        val expected = Codec.sha1(icaoMrzInformation.toByteArray(Charsets.US_ASCII)).copyOf(16)
        assertArrayEquals(expected, key.bacKey().key)
        assertEquals("239ab9cb282daf66231dc5a4df6bfbae", Codec.hex(key.bacKey().key))
    }

    @Test
    fun paceMrzKeyIsTheFullSha1OfTheMrzInformation() {
        val paceKey = AccessKey.Mrz("L898902C", "690806", "940623").paceKey()
        assertEquals(PassportService.MRZ_PACE_KEY_REFERENCE, paceKey.keyReference)
        assertArrayEquals(Codec.sha1(icaoMrzInformation.toByteArray(Charsets.US_ASCII)), paceKey.key)
    }

    @Test
    fun paceCanKeyCarriesTheCanReference() {
        val paceKey = AccessKey.Can("123456").paceKey()
        assertEquals(PassportService.CAN_PACE_KEY_REFERENCE, paceKey.keyReference)
        assertArrayEquals("123456".toByteArray(Charsets.US_ASCII), paceKey.key)
    }

    @Test
    fun toStringNeverRevealsTheKey() {
        assertFalse(AccessKey.Can("123456").toString().contains("123456"))
        val mrz = AccessKey.Mrz("L898902C", "690806", "940623").toString()
        assertFalse(mrz.contains("L898902C") || mrz.contains("690806") || mrz.contains("940623"))
        val form = AccessKeyForm(AccessKeyMode.MRZ, "123456", "L898902C", "690806", "940623").toString()
        assertFalse(form.contains("123456") || form.contains("L898902C") || form.contains("690806"))
    }

    @Test
    fun formValidatesOnlyTheSelectedMode() {
        val canForm = AccessKeyForm(mode = AccessKeyMode.CAN, can = "123456")
        assertTrue(canForm.problems().isEmpty())
        assertTrue(canForm.toAccessKey() is AccessKey.Can)

        val mrzForm = canForm.copy(mode = AccessKeyMode.MRZ)
        assertEquals(3, mrzForm.problems().size)
        val filled = mrzForm.copy(documentNumber = "L898902C", dateOfBirth = "690806", dateOfExpiry = "940623")
        assertTrue(filled.problems().isEmpty())
        assertEquals(AccessKeyKind.MRZ, filled.toAccessKey().kind)
    }

    @Test
    fun wrongKeyErrorsNameTheKeyThatWasRejected() {
        val can = ReadException.WrongAccessKey(AccessKeyKind.CAN, AccessProtocol.PACE, 0x63C2)
        assertEquals("Wrong CAN", can.title)
        assertEquals("PACE rejected the CAN (SW 63C2), 2 attempts left", can.message)

        val paceMrz = ReadException.WrongAccessKey(AccessKeyKind.MRZ, AccessProtocol.PACE, 0x6300)
        assertEquals("Wrong MRZ data", paceMrz.title)
        assertEquals("PACE rejected the MRZ data (SW 6300)", paceMrz.message)
        assertTrue(paceMrz.hint.contains("date of birth"))

        val bac = ReadException.WrongAccessKey(AccessKeyKind.MRZ, AccessProtocol.BAC, 0x6982)
        assertEquals("BAC rejected the MRZ data (SW 6982)", bac.message)
    }

    @Test
    fun rejectionStatusWords() {
        assertTrue(ReadException.WrongAccessKey.isRejection(AccessProtocol.PACE, 0x6300))
        assertTrue(ReadException.WrongAccessKey.isRejection(AccessProtocol.PACE, 0x63C1))
        assertFalse(ReadException.WrongAccessKey.isRejection(AccessProtocol.PACE, 0x6982))
        assertFalse(ReadException.WrongAccessKey.isRejection(AccessProtocol.PACE, 0x6A80))
        assertFalse(ReadException.WrongAccessKey.isRejection(AccessProtocol.PACE, null))
        assertTrue(ReadException.WrongAccessKey.isRejection(AccessProtocol.BAC, 0x6300))
        assertTrue(ReadException.WrongAccessKey.isRejection(AccessProtocol.BAC, 0x6982))
        assertFalse(ReadException.WrongAccessKey.isRejection(AccessProtocol.BAC, 0x6D00))
    }

    @Test
    fun paceMutualAuthenticationAnsweredWith6988IsAWrongKey() {
        val mutualAuth = ReadException.WrongAccessKey.PACE_MUTUAL_AUTH_STEP
        assertTrue(ReadException.WrongAccessKey.isRejection(AccessProtocol.PACE, 0x6988, mutualAuth))
        assertFalse(ReadException.WrongAccessKey.isRejection(AccessProtocol.PACE, 0x6988, 2))
        assertFalse(ReadException.WrongAccessKey.isRejection(AccessProtocol.PACE, 0x6988, 3))
        assertFalse(ReadException.WrongAccessKey.isRejection(AccessProtocol.PACE, 0x6988))
        assertFalse(ReadException.WrongAccessKey.isRejection(AccessProtocol.BAC, 0x6988, mutualAuth))

        val mrz = ReadException.WrongAccessKey(AccessKeyKind.MRZ, AccessProtocol.PACE, 0x6988)
        assertEquals("Wrong MRZ data", mrz.title)
        assertEquals("PACE rejected the MRZ data (SW 6988)", mrz.message)
        assertTrue(mrz.hint.contains("date of birth"))

        val can = ReadException.WrongAccessKey(AccessKeyKind.CAN, AccessProtocol.PACE, 0x6988)
        assertEquals("Wrong CAN", can.title)
        assertEquals("PACE rejected the CAN (SW 6988)", can.message)
        assertTrue(can.hint.contains("6-digit CAN"))
    }
}
