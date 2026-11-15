package dev.eudisovereign.icaowallet.report

import dev.eudisovereign.icaowallet.crypto.Codec
import dev.eudisovereign.icaowallet.data.Enrollment
import dev.eudisovereign.icaowallet.nfc.DocumentSecurity
import dev.eudisovereign.icaowallet.protocol.Derivation
import dev.eudisovereign.icaowallet.protocol.mrzOf
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException

enum class SodCoverage(val label: String) {
    MATCH("matches EF.SOD"),
    MISMATCH("DIFFERS from EF.SOD"),
    NOT_LISTED("no entry in EF.SOD"),
    NOT_COVERED("not covered by EF.SOD"),
}

class FileRow(val name: String, val size: Int, val digestHex: String, val coverage: SodCoverage)

class TechnicalReport(
    val enrollment: Enrollment,
    val mrz: Mrz?,
    val mrzError: String?,
    val files: List<FileRow>,
    val filesError: String?,
    val aaChallengeHex: String?,
    val attestation: AttestationSummary?,
    val attestationError: String?,
    val attestationChallengeHex: String,
    val deviceKeySha256Hex: String,
)

object DocumentReport {

    fun build(enrollment: Enrollment): TechnicalReport {
        var mrzError: String? = null
        val mrz = try {
            Mrz.parse(mrzOf(enrollment.dg1))
        } catch (e: IllegalArgumentException) {
            mrzError = e.message ?: "EF.DG1 cannot be parsed"
            null
        }

        var filesError: String? = null
        val files = try {
            val parsed = DocumentSecurity.parseSod(enrollment.sod)
            val dataGroups = listOfNotNull(
                1 to enrollment.dg1,
                enrollment.dg14?.let { 14 to it },
                enrollment.dg15?.let { 15 to it },
            ).toMap()
            fileRows(parsed.summary.ldsHashAlgorithm, parsed.dataGroupHashes, enrollment.cardAccess, enrollment.sod, dataGroups)
        } catch (e: IllegalArgumentException) {
            filesError = e.message ?: "EF.SOD cannot be parsed"
            emptyList()
        }

        var attestationError: String? = null
        val attestation = enrollment.keyAttestation.takeIf { it.isNotEmpty() }?.let {
            try {
                Attestation.summarize(it)
            } catch (e: IllegalArgumentException) {
                attestationError = e.message
                null
            }
        }

        return TechnicalReport(
            enrollment = enrollment,
            mrz = mrz,
            mrzError = mrzError,
            files = files,
            filesError = filesError,
            aaChallengeHex = enrollment.aaResponse?.let { Codec.hex(Derivation.aaChallenge(enrollment.devicePublicKey)) },
            attestation = attestation,
            attestationError = attestationError,
            attestationChallengeHex = Codec.hex(Derivation.attestationChallenge(enrollment.sod)),
            deviceKeySha256Hex = Codec.hex(Codec.sha256(enrollment.devicePublicKey)),
        )
    }

    fun fileRows(
        algorithm: String,
        sodHashes: Map<Int, ByteArray>,
        cardAccess: ByteArray?,
        sod: ByteArray,
        dataGroups: Map<Int, ByteArray>,
    ): List<FileRow> {
        fun digest(bytes: ByteArray): ByteArray = try {
            Codec.digest(algorithm, bytes)
        } catch (e: NoSuchAlgorithmException) {
            throw IllegalArgumentException("Unsupported LDS hash algorithm $algorithm", e)
        }

        val rows = mutableListOf<FileRow>()
        if (cardAccess != null) {
            rows += FileRow("EF.CardAccess", cardAccess.size, Codec.hex(digest(cardAccess)), SodCoverage.NOT_COVERED)
        }
        rows += FileRow("EF.SOD", sod.size, Codec.hex(digest(sod)), SodCoverage.NOT_COVERED)
        for ((number, bytes) in dataGroups.toSortedMap()) {
            val actual = digest(bytes)
            val expected = sodHashes[number]
            val coverage = when {
                expected == null -> SodCoverage.NOT_LISTED
                MessageDigest.isEqual(actual, expected) -> SodCoverage.MATCH
                else -> SodCoverage.MISMATCH
            }
            rows += FileRow("EF.DG$number", bytes.size, Codec.hex(actual), coverage)
        }
        return rows
    }
}
