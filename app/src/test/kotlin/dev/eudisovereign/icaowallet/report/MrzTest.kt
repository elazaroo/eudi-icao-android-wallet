package dev.eudisovereign.icaowallet.report

import dev.eudisovereign.icaowallet.protocol.mrzOf
import dev.eudisovereign.icaowallet.protocol.tamperDg1
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class MrzTest {

    // ICAO 9303-5 TD1 specimen
    private val td1 = "I<UTOD231458907<<<<<<<<<<<<<<<" +
        "7408122F1204159UTO<<<<<<<<<<<6" +
        "ERIKSSON<<ANNA<MARIA<<<<<<<<<<"

    // ICAO 9303-4 TD3 specimen
    private val td3 = "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<" +
        "L898902C36UTO7408122F1204159ZE184226B<<<<<10"

    @Test
    fun checkDigitFollowsIcaoWeights() {
        assertEquals('7', Mrz.checkDigit("D23145890"))
        assertEquals('2', Mrz.checkDigit("740812"))
        assertEquals('9', Mrz.checkDigit("120415"))
        assertEquals('0', Mrz.checkDigit("<<<<<<"))
        assertThrows(IllegalArgumentException::class.java) { Mrz.checkDigit("abc") }
    }

    @Test
    fun parsesTd1Specimen() {
        val mrz = Mrz.parse(td1)
        assertEquals(MrzFormat.TD1, mrz.format)
        assertEquals(3, mrz.lines.size)
        assertEquals("I", mrz.documentCode)
        assertEquals("UTO", mrz.issuingState)
        assertEquals("D23145890", mrz.documentNumber)
        assertEquals("740812", mrz.dateOfBirth)
        assertEquals("F", mrz.sex)
        assertEquals("120415", mrz.dateOfExpiry)
        assertEquals("UTO", mrz.nationality)
        assertEquals("ERIKSSON", mrz.primaryIdentifier)
        assertEquals("ANNA MARIA", mrz.secondaryIdentifier)
        assertEquals("", mrz.optionalData1)
        assertNull(mrz.optionalData1Valid)
        assertTrue(mrz.checksValid)
        assertEquals("Identity card (TD1)", mrz.documentType)
    }

    @Test
    fun parsesTd3Specimen() {
        val mrz = Mrz.parse(td3)
        assertEquals(MrzFormat.TD3, mrz.format)
        assertEquals("P", mrz.documentCode)
        assertEquals("L898902C3", mrz.documentNumber)
        assertEquals("ZE184226B", mrz.optionalData1)
        assertEquals(true, mrz.optionalData1Valid)
        assertNull(mrz.optionalData2)
        assertTrue(mrz.checksValid)
        assertEquals("Passport (TD3)", mrz.documentType)
        assertEquals("Personal number", mrz.fields()[3].label)
    }

    @Test
    fun td1DocumentNumberLongerThanNineCharactersContinuesInOptionalData() {
        val extended = "I<UTOD23145890<7349<<<<<<<<<<<" + td1.substring(30)
        val mrz = Mrz.parse(extended)
        assertEquals("D23145890734", mrz.documentNumber)
        assertTrue(mrz.documentNumberValid)
    }

    @Test
    fun alteredDg1FailsDocumentNumberAndCompositeChecks() {
        val dg1 = dg1Of(td1)
        assertTrue(Mrz.parse(mrzOf(dg1)).checksValid)
        val altered = Mrz.parse(mrzOf(tamperDg1(dg1)))
        assertEquals("E23145890", altered.documentNumber)
        assertFalse(altered.documentNumberValid)
        assertFalse(altered.compositeValid)
        assertTrue(altered.dateOfBirthValid)
    }

    @Test
    fun rejectsUnknownLengthAndAlphabet() {
        assertThrows(IllegalArgumentException::class.java) { Mrz.parse(td1.dropLast(1)) }
        assertThrows(IllegalArgumentException::class.java) { Mrz.parse(td1.lowercase()) }
    }

    companion object {
        // ICAO 9303-10 4.7.1: '61' L '5F1F' L MRZ
        fun dg1Of(mrz: String): ByteArray {
            val bytes = mrz.toByteArray(Charsets.US_ASCII)
            val inner = byteArrayOf(0x5F, 0x1F, bytes.size.toByte()) + bytes
            return byteArrayOf(0x61, inner.size.toByte()) + inner
        }
    }
}
