package dev.eudisovereign.icaowallet.report

import dev.eudisovereign.icaowallet.nfc.DocumentSecurity
import java.io.ByteArrayInputStream
import java.io.IOException
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import javax.security.auth.x500.X500Principal
import org.bouncycastle.asn1.ASN1Boolean
import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1Enumerated
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.ASN1Set
import org.bouncycastle.asn1.ASN1TaggedObject
import org.bouncycastle.asn1.BERTags

class CertificateSummary(
    val subject: String,
    val issuer: String,
    val serialHex: String,
    val notBeforeMillis: Long,
    val notAfterMillis: Long,
    val publicKey: String,
    val hasKeyDescription: Boolean,
)

class AttestationApplicationId(val packages: List<Pair<String, Long>>, val signatureDigests: List<ByteArray>)

class RootOfTrust(val deviceLocked: Boolean, val verifiedBootState: Int)

class KeyDescription(
    val attestationVersion: Int,
    val attestationSecurityLevel: Int,
    val keyMintVersion: Int,
    val keyMintSecurityLevel: Int,
    val attestationChallenge: ByteArray,
    val applicationId: AttestationApplicationId?,
    val rootOfTrust: RootOfTrust?,
)

/** The certificate of a chain that leaves its validity period first; [index] counts from the leaf. */
class ChainExpiry(val index: Int, val subject: String, val notAfterMillis: Long) {
    // RFC 5280 4.1.2.5: notAfter is the last instant at which the certificate is valid
    fun isExpired(nowMillis: Long): Boolean = nowMillis > notAfterMillis
}

class AttestationSummary(
    val certificates: List<CertificateSummary>,
    val keyDescription: KeyDescription?,
    val keyDescriptionError: String?,
) {
    val expiry: ChainExpiry? = certificates.withIndex()
        .minByOrNull { it.value.notAfterMillis }
        ?.let { ChainExpiry(it.index, it.value.subject, it.value.notAfterMillis) }
}

object Attestation {

    // Android Key Attestation, KeyDescription extension
    const val KEY_DESCRIPTION_OID = "1.3.6.1.4.1.11129.2.1.17"

    private const val TAG_ROOT_OF_TRUST = 704
    private const val TAG_APPLICATION_ID = 709

    /** Null for an empty chain; throws IllegalArgumentException when a certificate cannot be parsed. */
    fun chainExpiry(chain: List<ByteArray>): ChainExpiry? = summarize(chain).expiry

    fun summarize(chain: List<ByteArray>): AttestationSummary {
        val factory = CertificateFactory.getInstance("X.509")
        val certificates = chain.mapIndexed { index, der ->
            try {
                factory.generateCertificate(ByteArrayInputStream(der)) as X509Certificate
            } catch (e: CertificateException) {
                throw IllegalArgumentException("Attestation certificate $index cannot be parsed: ${e.message}", e)
            }
        }
        val summaries = certificates.map { cert ->
            CertificateSummary(
                subject = cert.subjectX500Principal.getName(X500Principal.RFC2253),
                issuer = cert.issuerX500Principal.getName(X500Principal.RFC2253),
                serialHex = cert.serialNumber.toString(16),
                notBeforeMillis = cert.notBefore.time,
                notAfterMillis = cert.notAfter.time,
                publicKey = DocumentSecurity.describeKey(cert.publicKey),
                hasKeyDescription = cert.getExtensionValue(KEY_DESCRIPTION_OID) != null,
            )
        }
        val extension = certificates.firstOrNull()?.getExtensionValue(KEY_DESCRIPTION_OID)
        var error: String? = null
        val description = extension?.let {
            try {
                parseKeyDescription(it)
            } catch (e: IllegalArgumentException) {
                error = "KeyDescription cannot be parsed: ${e.message}"
                null
            }
        }
        if (extension == null && certificates.isNotEmpty()) error = "The leaf certificate has no KeyDescription extension"
        return AttestationSummary(summaries, description, error)
    }

    /** [extensionValue] is the DER OCTET STRING returned by X509Certificate.getExtensionValue. */
    fun parseKeyDescription(extensionValue: ByteArray): KeyDescription = try {
        val inner = ASN1OctetString.getInstance(ASN1Primitive.fromByteArray(extensionValue)).octets
        val sequence = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(inner))
        require(sequence.size() >= 8) { "KeyDescription has ${sequence.size()} elements, expected 8" }
        val softwareEnforced = ASN1Sequence.getInstance(sequence.getObjectAt(6))
        val hardwareEnforced = ASN1Sequence.getInstance(sequence.getObjectAt(7))
        val applicationId = (tagged(hardwareEnforced, TAG_APPLICATION_ID) ?: tagged(softwareEnforced, TAG_APPLICATION_ID))
            ?.let { parseApplicationId(ASN1OctetString.getInstance(it).octets) }
        val rootOfTrust = (tagged(hardwareEnforced, TAG_ROOT_OF_TRUST) ?: tagged(softwareEnforced, TAG_ROOT_OF_TRUST))
            ?.let(::parseRootOfTrust)
        KeyDescription(
            attestationVersion = ASN1Integer.getInstance(sequence.getObjectAt(0)).intValueExact(),
            attestationSecurityLevel = ASN1Enumerated.getInstance(sequence.getObjectAt(1)).intValueExact(),
            keyMintVersion = ASN1Integer.getInstance(sequence.getObjectAt(2)).intValueExact(),
            keyMintSecurityLevel = ASN1Enumerated.getInstance(sequence.getObjectAt(3)).intValueExact(),
            attestationChallenge = ASN1OctetString.getInstance(sequence.getObjectAt(4)).octets,
            applicationId = applicationId,
            rootOfTrust = rootOfTrust,
        )
    } catch (e: IOException) {
        throw IllegalArgumentException("malformed DER: ${e.message}", e)
    } catch (e: ArithmeticException) {
        throw IllegalArgumentException("integer out of range", e)
    } catch (e: IllegalStateException) {
        throw IllegalArgumentException(e.message, e)
    }

    fun securityLevelName(level: Int): String = when (level) {
        0 -> "Software"
        1 -> "TrustedEnvironment"
        2 -> "StrongBox"
        else -> "unknown ($level)"
    }

    fun verifiedBootStateName(state: Int): String = when (state) {
        0 -> "Verified"
        1 -> "SelfSigned"
        2 -> "Unverified"
        3 -> "Failed"
        else -> "unknown ($state)"
    }

    private fun tagged(list: ASN1Sequence, tag: Int): ASN1Encodable? = list.toArray().firstNotNullOfOrNull { element ->
        (element as? ASN1TaggedObject)
            ?.takeIf { it.tagClass == BERTags.CONTEXT_SPECIFIC && it.tagNo == tag }
            ?.explicitBaseObject
    }

    // AttestationApplicationId ::= SEQUENCE { packageInfos SET OF SEQUENCE { packageName, version }, signatureDigests SET OF OCTET STRING }
    private fun parseApplicationId(der: ByteArray): AttestationApplicationId {
        val sequence = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(der))
        require(sequence.size() >= 2) { "AttestationApplicationId has ${sequence.size()} elements, expected 2" }
        val packages = ASN1Set.getInstance(sequence.getObjectAt(0)).toArray().map {
            val info = ASN1Sequence.getInstance(it)
            String(ASN1OctetString.getInstance(info.getObjectAt(0)).octets, Charsets.UTF_8) to
                ASN1Integer.getInstance(info.getObjectAt(1)).longValueExact()
        }
        val digests = ASN1Set.getInstance(sequence.getObjectAt(1)).toArray().map { ASN1OctetString.getInstance(it).octets }
        return AttestationApplicationId(packages, digests)
    }

    // RootOfTrust ::= SEQUENCE { verifiedBootKey, deviceLocked BOOLEAN, verifiedBootState ENUMERATED, ... }
    private fun parseRootOfTrust(element: ASN1Encodable): RootOfTrust {
        val sequence = ASN1Sequence.getInstance(element)
        require(sequence.size() >= 3) { "RootOfTrust has ${sequence.size()} elements, expected at least 3" }
        return RootOfTrust(
            deviceLocked = ASN1Boolean.getInstance(sequence.getObjectAt(1)).isTrue,
            verifiedBootState = ASN1Enumerated.getInstance(sequence.getObjectAt(2)).intValueExact(),
        )
    }
}
