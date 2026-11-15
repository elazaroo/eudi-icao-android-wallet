package dev.eudisovereign.icaowallet.zk

import dev.eudisovereign.icaowallet.crypto.Codec
import java.io.ByteArrayInputStream
import java.math.BigInteger
import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1Encoding
import org.bouncycastle.asn1.ASN1InputStream
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.ASN1Set
import org.bouncycastle.asn1.ASN1TaggedObject
import org.bouncycastle.asn1.BERTags
import org.bouncycastle.asn1.cms.ContentInfo
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber
import org.bouncycastle.asn1.cms.SignedData
import org.bouncycastle.asn1.cms.SignerInfo
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x509.Certificate
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier

internal class SodDataGroupHash(val number: Int, val hash: ByteArray)

/** The parts of EF.SOD the age proof needs, with the byte strings taken exactly as they stand in the file. */
internal class AgeProofSod(
    val eContent: ByteArray,
    val hashAlgorithm: AlgorithmIdentifier,
    val dataGroupHashes: List<SodDataGroupHash>,
    val digestAlgorithm: AlgorithmIdentifier,
    val signatureAlgorithm: AlgorithmIdentifier,
    /** signedAttrs under their [0] IMPLICIT tag; null when the SignerInfo has none. */
    val signedAttrs: ByteArray?,
    val signature: ByteArray,
    val dsCertificate: Certificate?,
    val dsCertificateDer: ByteArray?,
    val dsCertificateIssue: String?,
)

internal object AgeProofSodParser {
    private const val LDS_SOD_TAG = 0x77
    private const val SIGNED_DATA = "1.2.840.113549.1.7.2"
    private const val LDS_SECURITY_OBJECT = "2.23.136.1.1.1"

    fun parse(sodBytes: ByteArray): AgeProofSod = try {
        decode(sodBytes)
    } catch (e: AgeProofInputException) {
        throw e
    } catch (e: Exception) {
        val message = e.message ?: e.javaClass.simpleName
        throw AgeProofInputException(if (message.startsWith("EF.SOD")) message else "EF.SOD: $message", e)
    }

    private fun fail(message: String): Nothing = throw IllegalArgumentException(message)

    private fun unwrap(file: ByteArray): ByteArray {
        if (file.isEmpty()) fail("EF.SOD is empty")
        val tag = file[0].toInt() and 0xFF
        if (tag != LDS_SOD_TAG) fail("EF.SOD must start with tag 0x77, found 0x%02X".format(tag))
        if (file.size < 2) fail("EF.SOD: truncated length")
        val first = file[1].toInt() and 0xFF
        var offset = 2
        val length = when {
            first < 0x80 -> first.toLong()
            first == 0x80 -> fail("EF.SOD: the 0x77 data object uses an indefinite length")
            first - 0x80 > 4 -> fail("EF.SOD: unsupported length of ${first - 0x80} bytes")
            else -> {
                var value = 0L
                repeat(first - 0x80) {
                    if (offset >= file.size) fail("EF.SOD: truncated length")
                    value = (value shl 8) or (file[offset++].toLong() and 0xFF)
                }
                value
            }
        }
        val end = offset + length
        if (end > file.size) fail("EF.SOD: the 0x77 data object runs past the end of the file")
        if (end < file.size) fail("EF.SOD: ${file.size - end} trailing bytes after the 0x77 data object")
        return file.copyOfRange(offset, end.toInt())
    }

    private fun decode(sodBytes: ByteArray): AgeProofSod {
        val content = unwrap(sodBytes)
        val root = ASN1InputStream(ByteArrayInputStream(content), content.size).use { stream ->
            val first = stream.readObject() ?: fail("the 0x77 data object is empty")
            if (stream.readObject() != null) fail("trailing data after ContentInfo")
            first
        }
        val contentInfo = try {
            ContentInfo.getInstance(root)
        } catch (e: IllegalArgumentException) {
            fail("the 0x77 data object does not hold a CMS ContentInfo")
        }
        if (contentInfo.contentType.id != SIGNED_DATA) {
            fail("ContentInfo.contentType is ${contentInfo.contentType.id}, expected $SIGNED_DATA")
        }
        val signedData = SignedData.getInstance(contentInfo.content)
        val encapsulated = signedData.encapContentInfo
        if (encapsulated.contentType.id != LDS_SECURITY_OBJECT) {
            fail("eContentType is ${encapsulated.contentType.id}, expected $LDS_SECURITY_OBJECT")
        }
        val eContentNode = encapsulated.content
            ?: fail("encapContentInfo carries no eContent: a detached signature is not a valid EF.SOD")
        val eContent = ASN1OctetString.getInstance(eContentNode).octets
        if (signedData.signerInfos.size() != 1) {
            fail("SignedData must contain exactly one SignerInfo, found ${signedData.signerInfos.size()}")
        }
        val signerNode = ASN1Sequence.getInstance(signedData.signerInfos.getObjectAt(0))
        val signer = SignerInfo.getInstance(signerNode)
        val (hashAlgorithm, dataGroupHashes) = parseLdsSecurityObject(eContent)

        val signedAttrs = signer.authenticatedAttributes?.let { set -> signedAttrsBytes(signerNode, set, content) }
        val sid = signer.sid
        // SignerIdentifier.getId() already unwraps subjectKeyIdentifier [0] IMPLICIT OCTET STRING
        val subjectKeyId = if (sid.isTagged) ASN1OctetString.getInstance(sid.id).octets else null
        val issuerAndSerial = if (sid.isTagged) null else IssuerAndSerialNumber.getInstance(sid.id)
        val expectedVersion = if (issuerAndSerial != null) 1 else 3
        if (signer.version.value != BigInteger.valueOf(expectedVersion.toLong())) {
            fail(
                "SignerInfo version ${signer.version.value} does not match the sid: RFC 5652 5.3 requires 1 for " +
                    "issuerAndSerialNumber and 3 for subjectKeyIdentifier",
            )
        }

        val certificates = mutableListOf<Pair<Certificate, ByteArray>>()
        val rejected = mutableListOf<String>()
        signedData.certificates?.let { set ->
            for (position in 0 until set.size()) {
                val choice = set.getObjectAt(position).toASN1Primitive()
                if (choice !is ASN1Sequence) {
                    rejected += "entry ${position + 1}: not an X.509 certificate"
                    continue
                }
                try {
                    val der = choice.getEncoded(ASN1Encoding.DL)
                    if (indexOf(content, der) < 0) throw IllegalArgumentException("not encoded as DER in the file")
                    certificates += Certificate.getInstance(choice) to der
                } catch (e: Exception) {
                    rejected += "entry ${position + 1}: ${e.message ?: e.javaClass.simpleName}"
                }
            }
        }
        val describeSid = if (issuerAndSerial != null) {
            "issuer ${issuerAndSerial.name}, serial number ${issuerAndSerial.serialNumber.value.toString(16)}"
        } else {
            "subjectKeyIdentifier ${Codec.hex(subjectKeyId!!)}"
        }
        val matches = certificates
            .filter { (certificate, _) -> matchesSid(certificate, issuerAndSerial, subjectKeyId) }
            .distinctBy { (_, der) -> der.toList() }
        val issue = when {
            matches.isEmpty() ->
                "no certificate in SignedData.certificates matches the SignerInfo sid ($describeSid)" +
                    if (rejected.isNotEmpty()) "; rejected entries: ${rejected.joinToString("; ")}" else ""
            matches.size > 1 -> "${matches.size} different certificates match the SignerInfo sid ($describeSid)"
            else -> null
        }
        val ds = matches.singleOrNull()

        return AgeProofSod(
            eContent = eContent,
            hashAlgorithm = hashAlgorithm,
            dataGroupHashes = dataGroupHashes,
            digestAlgorithm = signer.digestAlgorithm,
            signatureAlgorithm = signer.digestEncryptionAlgorithm,
            signedAttrs = signedAttrs,
            signature = signer.encryptedDigest.octets,
            dsCertificate = ds?.first,
            dsCertificateDer = ds?.second,
            dsCertificateIssue = issue,
        )
    }

    // RFC 5652 5.4: the signature covers the DER encoding, so only DER is accepted for this subtree.
    private fun signedAttrsBytes(signerNode: ASN1Sequence, set: ASN1Set, file: ByteArray): ByteArray {
        val tagged = (0 until signerNode.size()).map { signerNode.getObjectAt(it) }
            .filterIsInstance<ASN1TaggedObject>()
            .firstOrNull { it.tagClass == BERTags.CONTEXT_SPECIFIC && it.tagNo == 0 }
            ?: fail("signedAttrs were not retained in encoded form")
        val encoded = tagged.getEncoded(ASN1Encoding.DL)
        if (encoded.isEmpty() || (encoded[0].toInt() and 0xFF) != 0xA0) fail("signedAttrs were not retained in encoded form")
        val der = set.getEncoded(ASN1Encoding.DER)
        if (der.size != encoded.size || !der.copyOfRange(1, der.size).contentEquals(encoded.copyOfRange(1, encoded.size))) {
            fail("signedAttrs are not DER encoded")
        }
        if (indexOf(file, encoded) < 0) fail("signedAttrs are not DER encoded")
        return encoded
    }

    private fun matchesSid(certificate: Certificate, issuerAndSerial: IssuerAndSerialNumber?, subjectKeyId: ByteArray?): Boolean {
        if (issuerAndSerial != null) {
            return X500Name.getInstance(certificate.issuer) == issuerAndSerial.name &&
                certificate.serialNumber.value == issuerAndSerial.serialNumber.value
        }
        val extension = certificate.tbsCertificate.extensions?.getExtension(Extension.subjectKeyIdentifier) ?: return false
        return SubjectKeyIdentifier.getInstance(extension.parsedValue).keyIdentifier.contentEquals(subjectKeyId)
    }

    // ICAO 9303-10 4.6.2.3: LDSSecurityObject ::= SEQUENCE { version, hashAlgorithm, dataGroupHashValues,
    // ldsVersionInfo OPTIONAL }
    private fun parseLdsSecurityObject(eContent: ByteArray): Pair<AlgorithmIdentifier, List<SodDataGroupHash>> {
        val fields = try {
            ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(eContent))
        } catch (e: Exception) {
            fail("LDSSecurityObject is not a DER SEQUENCE: ${e.message}")
        }
        if (fields.size() < 3 || fields.size() > 4) {
            fail("LDSSecurityObject must have three or four elements, found ${fields.size()}")
        }
        val version = ASN1Integer.getInstance(fields.getObjectAt(0)).value
        if (version > BigInteger.ONE || version.signum() < 0) fail("LDSSecurityObject version $version is not defined")
        val hashAlgorithm = try {
            AlgorithmIdentifier.getInstance(fields.getObjectAt(1))
        } catch (e: IllegalArgumentException) {
            fail("LDSSecurityObject.hashAlgorithm is not an AlgorithmIdentifier")
        }
        val seen = mutableSetOf<Int>()
        val hashes = ASN1Sequence.getInstance(fields.getObjectAt(2)).map { entry: ASN1Encodable ->
            val parts = ASN1Sequence.getInstance(entry)
            if (parts.size() != 2) fail("DataGroupHash must have two elements, found ${parts.size()}")
            val number = ASN1Integer.getInstance(parts.getObjectAt(0)).value
            if (number < BigInteger.ONE || number > BigInteger.valueOf(16)) fail("data group number $number is outside 1..16")
            if (!seen.add(number.toInt())) fail("data group $number is listed more than once")
            SodDataGroupHash(number.toInt(), ASN1OctetString.getInstance(parts.getObjectAt(1)).octets)
        }
        return hashAlgorithm to hashes
    }

    fun indexOf(haystack: ByteArray, needle: ByteArray): Int {
        if (needle.isEmpty() || needle.size > haystack.size) return -1
        outer@ for (offset in 0..haystack.size - needle.size) {
            for (i in needle.indices) if (haystack[offset + i] != needle[i]) continue@outer
            return offset
        }
        return -1
    }
}
