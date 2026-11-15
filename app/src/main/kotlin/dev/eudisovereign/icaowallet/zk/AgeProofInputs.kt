package dev.eudisovereign.icaowallet.zk

import dev.eudisovereign.icaowallet.crypto.Codec
import java.math.BigInteger
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import org.bouncycastle.asn1.ASN1Null
import org.bouncycastle.asn1.pkcs.RSAPublicKey
import org.bouncycastle.asn1.x509.AlgorithmIdentifier

class AgeProofInputException(message: String, cause: Throwable? = null) : Exception(message, cause)

/** Witness inputs of circuits/age_proof.circom as decimal strings, as in src/zk/inputs.ts. */
@Serializable
class AgeProofInputs(
    val signedAttrs: List<String>,
    val signedAttrsLength: String,
    val contentTypeOffset: String,
    val messageDigestOffset: String,
    val eContent: List<String>,
    val eContentLength: String,
    val dg1: List<String>,
    val signature: List<String>,
    val modulus: List<String>,
    val currentDate: String,
    val ageThreshold: String,
    val challenge: String,
) {
    fun toJson(): String = json.encodeToString(serializer(), this)

    private companion object {
        val json = Json { encodeDefaults = true }
    }
}

class AgeProofStatement(val currentDate: Int, val ageThreshold: Int, val challenge: BigInteger)

enum class MrzProfile { TD1, TD3 }

enum class HashParameters { ABSENT, NULL }

class PreparedAgeProof(
    val inputs: AgeProofInputs,
    /** DER of the Document Signer certificate carried in EF.SOD; it travels in clear next to the proof. */
    val dsCertificate: ByteArray,
    val modulus: BigInteger,
    val profile: MrzProfile,
    val hashParameters: HashParameters,
    val signedAttrsLength: Int,
    val eContentLength: Int,
)

private val CONTENT_TYPE_ATTRIBUTE = bytes(
    0x30, 0x15, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x03, 0x31, 0x08, 0x06, 0x06, 0x67, 0x81,
    0x08, 0x01, 0x01, 0x01,
)
private val MESSAGE_DIGEST_ATTRIBUTE = bytes(
    0x30, 0x2f, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04, 0x31, 0x22, 0x04, 0x20,
)
private val SHA1_ALGORITHM = bytes(0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a)
private val DG1_ENTRY = bytes(0x30, 0x19, 0x02, 0x01, 0x01, 0x04, 0x14)
private val TD1_HEADER = bytes(0x61, 0x5d, 0x5f, 0x1f, 0x5a)
private val TD3_HEADER = bytes(0x61, 0x5b, 0x5f, 0x1f, 0x58)

private const val OID_SHA1 = "1.3.14.3.2.26"
private const val OID_SHA256 = "2.16.840.1.101.3.4.2.1"
private const val OID_RSA_ENCRYPTION = "1.2.840.113549.1.1.1"
private const val OID_SHA256_WITH_RSA = "1.2.840.113549.1.1.11"
private const val OID_RSASSA_PSS = "1.2.840.113549.1.1.10"

private fun bytes(vararg values: Int): ByteArray = ByteArray(values.size) { values[it].toByte() }

private fun ByteArray.u(index: Int): Int = this[index].toInt() and 0xFF

private fun ByteArray.slice(from: Int, to: Int): ByteArray = copyOfRange(from.coerceAtMost(size), to.coerceAtMost(size))

/** FIPS 180-4 5.1.1, for SHA-1 and SHA-256 alike, then zero-filled to [maxBlocks] blocks. */
fun shaPad(message: ByteArray, maxBlocks: Int): ByteArray {
    val blocks = (message.size + 8) / 64 + 1
    if (blocks > maxBlocks) {
        throw AgeProofInputException(
            "${message.size} bytes need $blocks SHA blocks, the circuit takes at most $maxBlocks",
        )
    }
    val out = ByteArray(maxBlocks * 64)
    message.copyInto(out)
    out[message.size] = 0x80.toByte()
    val bits = message.size.toLong() * 8
    val end = blocks * 64
    for (i in 0 until 4) out[end - 1 - i] = ((bits ushr (8 * i)) and 0xFF).toByte()
    return out
}

private fun occurrences(haystack: ByteArray, needle: ByteArray): List<Int> =
    (0..haystack.size - needle.size).filter { offset ->
        needle.indices.all { haystack[offset + it] == needle[it] }
    }

private fun singleOffset(signedAttrs: ByteArray, pattern: ByteArray, name: String, valueLength: Int): Int {
    val found = occurrences(signedAttrs, pattern)
    if (found.size != 1) {
        throw AgeProofInputException("signedAttrs must contain the $name attribute exactly once, found ${found.size}")
    }
    val offset = found[0]
    if (offset + pattern.size + valueLength > signedAttrs.size) {
        throw AgeProofInputException("the $name attribute runs past the end of signedAttrs")
    }
    return offset
}

/** Mirrors check 3 of the circuit so that an unsupported layout is reported before a witness is attempted. */
fun eContentLayout(eContent: ByteArray): HashParameters {
    fun fail(what: String): Nothing = throw AgeProofInputException(
        "eContent does not have the layout the circuit accepts: $what (starts ${Codec.hex(eContent.slice(0, 32))})",
    )
    if (eContent.size < 47) fail("shorter than 47 bytes")
    if (eContent.u(0) != 0x30 || eContent.u(1) != 0x81) fail("not a SEQUENCE with a one-byte long-form length")
    if (eContent.u(3) != 0x02 || eContent.u(4) != 0x01 || eContent.u(5) != 0x00) fail("LDSSecurityObject version is not 0")
    if (eContent.u(6) != 0x30 || !eContent.slice(8, 15).contentEquals(SHA1_ALGORITHM)) fail("hashAlgorithm is not SHA-1")
    var shift = 0
    if (eContent.u(7) == 0x09) {
        if (eContent.u(15) != 0x05 || eContent.u(16) != 0x00) fail("hashAlgorithm parameters are neither absent nor NULL")
        shift = 2
    } else if (eContent.u(7) != 0x07) {
        fail("hashAlgorithm parameters are neither absent nor NULL")
    }
    if (eContent.u(15 + shift) != 0x30 || eContent.u(16 + shift) != 0x81) {
        fail("dataGroupHashValues is not a SEQUENCE with a one-byte long-form length")
    }
    if (!eContent.slice(18 + shift, 25 + shift).contentEquals(DG1_ENTRY)) {
        fail("the first data group hash is not a 20-byte hash of DG1")
    }
    return if (shift == 2) HashParameters.NULL else HashParameters.ABSENT
}

private fun decimal(bytes: ByteArray): List<String> = bytes.map { (it.toInt() and 0xFF).toString() }

private fun decimal(values: List<BigInteger>): List<String> = values.map(BigInteger::toString)

private fun hasNoParameters(algorithm: AlgorithmIdentifier): Boolean =
    algorithm.parameters == null || algorithm.parameters is ASN1Null

// The scheme of resolveSignatureScheme (src/crypto/signature.ts) restricted to the one the circuit proves.
private fun isRsaPkcs1Sha256(signature: AlgorithmIdentifier, digest: AlgorithmIdentifier): Boolean =
    when (signature.algorithm.id) {
        OID_SHA256_WITH_RSA -> hasNoParameters(signature)
        // RFC 3370 3.2: rsaEncryption as SignerInfo.signatureAlgorithm, the hash is SignerInfo.digestAlgorithm
        OID_RSA_ENCRYPTION -> hasNoParameters(signature) && digest.algorithm.id == OID_SHA256 && hasNoParameters(digest)
        else -> false
    }

/**
 * Builds the witness inputs from the raw files as read from the chip. Port of prepareAgeProofInputs of the web
 * verifier; the cross-implementation vectors fix every value. [unsupportedLayout] skips the eContent layout
 * pre-check and only serves to exercise the circuit's own check.
 */
fun prepareAgeProofInputs(
    dg1: ByteArray,
    sodBytes: ByteArray,
    statement: AgeProofStatement,
    unsupportedLayout: Boolean = false,
): PreparedAgeProof {
    val sod = AgeProofSodParser.parse(sodBytes)
    if (!isRsaPkcs1Sha256(sod.signatureAlgorithm, sod.digestAlgorithm)) {
        throw AgeProofInputException("the circuit proves only RSASSA-PKCS1-v1_5 with SHA-256 SOD signatures")
    }
    if (sod.hashAlgorithm.algorithm.id != OID_SHA1) {
        throw AgeProofInputException("the circuit proves only SHA-1 data group hashes")
    }
    if (sod.dataGroupHashes.firstOrNull()?.number != 1) {
        throw AgeProofInputException("the first data group hash in EF.SOD is not that of DG1")
    }
    val ds = sod.dsCertificate
    val dsDer = sod.dsCertificateDer
    if (ds == null || dsDer == null) {
        throw AgeProofInputException(sod.dsCertificateIssue ?: "EF.SOD carries no Document Signer certificate")
    }
    val keyInfo = ds.subjectPublicKeyInfo
    val rsaKey = if (keyInfo.algorithm.algorithm.id == OID_RSA_ENCRYPTION) {
        try {
            RSAPublicKey.getInstance(keyInfo.parsePublicKey())
        } catch (e: Exception) {
            null
        }
    } else {
        null
    }
    if (rsaKey == null || keyInfo.algorithm.algorithm.id == OID_RSASSA_PSS ||
        rsaKey.modulus.bitLength() != AgeStatement.RSA_MODULUS_BITS || rsaKey.publicExponent != AgeStatement.RSA_EXPONENT
    ) {
        throw AgeProofInputException("the Document Signer key must be RSA-2048 with e = 65537")
    }
    val signedAttrsInFile = sod.signedAttrs ?: throw AgeProofInputException("SignerInfo carries no signedAttrs")

    // RFC 5652 5.4: the signature covers signedAttrs with the SET OF tag
    val signedAttrs = signedAttrsInFile.copyOf().also { it[0] = 0x31 }
    val contentTypeOffset = singleOffset(signedAttrs, CONTENT_TYPE_ATTRIBUTE, "contentType", 0)
    val messageDigestOffset = singleOffset(signedAttrs, MESSAGE_DIGEST_ATTRIBUTE, "messageDigest", 32)

    val hashParameters = if (unsupportedLayout) {
        if (sod.eContent.size > 7 && sod.eContent.u(7) == 0x09) HashParameters.NULL else HashParameters.ABSENT
    } else {
        eContentLayout(sod.eContent)
    }

    val profile = when {
        dg1.size == 95 && dg1.slice(0, 5).contentEquals(TD1_HEADER) -> MrzProfile.TD1
        dg1.size == 93 && dg1.slice(0, 5).contentEquals(TD3_HEADER) -> MrzProfile.TD3
        else -> throw AgeProofInputException(
            "EF.DG1 is neither a 95-byte TD1 nor a 93-byte TD3 MRZ data object " +
                "(${dg1.size} bytes, starts ${Codec.hex(dg1.slice(0, 5))})",
        )
    }

    val signature = BigInteger(1, sod.signature)
    val modulus = rsaKey.modulus
    if (signature >= modulus) throw AgeProofInputException("the SOD signature is not smaller than the modulus")
    if (statement.challenge.signum() < 0 || statement.challenge >= AgeStatement.FIELD_ORDER) {
        throw AgeProofInputException("the challenge is not a field element")
    }

    return PreparedAgeProof(
        inputs = AgeProofInputs(
            signedAttrs = decimal(shaPad(signedAttrs, AgeStatement.SIGNED_ATTRS_BLOCKS)),
            signedAttrsLength = signedAttrs.size.toString(),
            contentTypeOffset = contentTypeOffset.toString(),
            messageDigestOffset = messageDigestOffset.toString(),
            eContent = decimal(shaPad(sod.eContent, AgeStatement.ECONTENT_BLOCKS)),
            eContentLength = sod.eContent.size.toString(),
            dg1 = decimal(shaPad(dg1, AgeStatement.DG1_BLOCKS)),
            signature = decimal(AgeStatement.toLimbs(signature)),
            modulus = decimal(AgeStatement.toLimbs(modulus)),
            currentDate = statement.currentDate.toString(),
            ageThreshold = statement.ageThreshold.toString(),
            challenge = statement.challenge.toString(),
        ),
        dsCertificate = dsDer.copyOf(),
        modulus = modulus,
        profile = profile,
        hashParameters = hashParameters,
        signedAttrsLength = signedAttrs.size,
        eContentLength = sod.eContent.size,
    )
}

fun modulusLimbs(modulus: BigInteger): List<String> = decimal(AgeStatement.toLimbs(modulus))
