package dev.eudisovereign.icaowallet.report

import dev.eudisovereign.icaowallet.crypto.Codec
import dev.eudisovereign.icaowallet.crypto.KeyStorage
import dev.eudisovereign.icaowallet.data.Enrollment
import dev.eudisovereign.icaowallet.nfc.DocumentSecurity
import dev.eudisovereign.icaowallet.nfc.PaceDetails
import dev.eudisovereign.icaowallet.protocol.Binding
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assume.assumeTrue
import org.junit.Test

class DocumentReportTest {

    private val dg1 = MrzTest.dg1Of(
        "I<UTOD231458907<<<<<<<<<<<<<<<7408122F1204159UTO<<<<<<<<<<<6ERIKSSON<<ANNA<MARIA<<<<<<<<<<",
    )
    private val dg14 = byteArrayOf(0x6E, 0x01, 0x00)
    private val dg15 = byteArrayOf(0x6F, 0x01, 0x00)
    private val cardAccess = byteArrayOf(0x31, 0x00)
    private val sod = byteArrayOf(0x77, 0x00)

    @Test
    fun fileRowsCompareEachDataGroupWithItsSodEntry() {
        val hashes = mapOf(1 to Codec.sha256(dg1), 14 to Codec.sha256(byteArrayOf(1)))
        val rows = DocumentReport.fileRows("SHA-256", hashes, cardAccess, sod, mapOf(15 to dg15, 1 to dg1, 14 to dg14))

        assertEquals(listOf("EF.CardAccess", "EF.SOD", "EF.DG1", "EF.DG14", "EF.DG15"), rows.map { it.name })
        assertEquals(
            listOf(SodCoverage.NOT_COVERED, SodCoverage.NOT_COVERED, SodCoverage.MATCH, SodCoverage.MISMATCH,
                SodCoverage.NOT_LISTED),
            rows.map { it.coverage },
        )
        assertEquals(dg1.size, rows[2].size)
        assertEquals(Codec.hex(Codec.sha256(dg1)), rows[2].digestHex)
        assertEquals(Codec.hex(Codec.sha256(sod)), rows[1].digestHex)
    }

    @Test
    fun fileRowsUseTheSodHashAlgorithm() {
        val rows = DocumentReport.fileRows("SHA-1", mapOf(1 to Codec.sha1(dg1)), cardAccess, sod, mapOf(1 to dg1))
        assertEquals(SodCoverage.MATCH, rows.last().coverage)
        assertEquals(40, rows.last().digestHex.length)
        assertThrows(IllegalArgumentException::class.java) {
            DocumentReport.fileRows("SHA-0", emptyMap(), cardAccess, sod, mapOf(1 to dg1))
        }
    }

    @Test
    fun bacEnrolmentHasNoCardAccessRow() {
        val rows = DocumentReport.fileRows("SHA-256", mapOf(1 to Codec.sha256(dg1)), null, sod, mapOf(1 to dg1))
        assertEquals(listOf("EF.SOD", "EF.DG1"), rows.map { it.name })
    }

    @Test
    fun reportOverSpecimenSod() {
        val specimen = javaClass.getResourceAsStream("/external/SOD_ESPECIMEN.der")?.use { it.readBytes() }
        assumeTrue("SOD_ESPECIMEN.der is not available", specimen != null)
        val sodBytes = requireNotNull(specimen)
        val enrollment = Enrollment(
            cardAccess = cardAccess,
            sod = sodBytes,
            dg1 = dg1,
            dg14 = dg14,
            binding = Binding.CA_ATTESTATION,
            devicePublicKey = byteArrayOf(0x30, 0x59),
            keyAttestation = emptyList(),
            keyStorage = KeyStorage.TEE,
            pace = PaceDetails("0.4.0.127.0.7.2.2.4.2.2", "ECDH-GM AES-128", 13),
            sodSummary = DocumentSecurity.parseSod(sodBytes).summary,
            steps = emptyList(),
            enrolledAtMillis = 0L,
            deviceModel = "Test Device",
            osVersion = "Android 16",
        )

        val report = DocumentReport.build(enrollment)

        assertNull(report.filesError)
        assertEquals(
            listOf(SodCoverage.NOT_COVERED, SodCoverage.NOT_COVERED, SodCoverage.MISMATCH, SodCoverage.MISMATCH),
            report.files.map { it.coverage },
        )
        assertEquals(40, report.files[2].digestHex.length)
        assertEquals("D23145890", requireNotNull(report.mrz).documentNumber)
        assertNull(report.attestation)
        assertNull(report.aaChallengeHex)
        assertEquals(Codec.hex(Codec.sha256(sodBytes)), report.attestationChallengeHex)
        assertEquals(Codec.hex(Codec.sha256(byteArrayOf(0x30, 0x59))), report.deviceKeySha256Hex)
    }

    @Test
    fun policyFragmentIsTheAllowedAppsEntry() {
        val identity = BuildIdentity("dev.eudisovereign.icaowallet", listOf("00ff", "a1b2"), debuggable = true)
        assertEquals(
            """{"packageName":"dev.eudisovereign.icaowallet","signingCertSha256":["00ff","a1b2"]}""",
            identity.policyFragment(),
        )
    }
}
