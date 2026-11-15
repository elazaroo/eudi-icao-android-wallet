package dev.eudisovereign.icaowallet.report

import dev.eudisovereign.icaowallet.crypto.Codec
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.time.Instant
import java.util.Date
import org.bouncycastle.asn1.ASN1Boolean
import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1Enumerated
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.DERBitString
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.DERSet
import org.bouncycastle.asn1.DERTaggedObject
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.asn1.x509.Time
import org.bouncycastle.asn1.x509.V3TBSCertificateGenerator
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class AttestationTest {

    private val challenge = Codec.sha256("sod".toByteArray())
    private val signerDigest = Codec.sha256("signing certificate".toByteArray())

    private fun sequence(vararg items: ASN1Encodable) = DERSequence(arrayOf(*items))

    private fun keyDescription(softwareEnforced: DERSequence, hardwareEnforced: DERSequence): ByteArray {
        val description = sequence(
            ASN1Integer(300),
            ASN1Enumerated(2),
            ASN1Integer(300),
            ASN1Enumerated(1),
            DEROctetString(challenge),
            DEROctetString(ByteArray(0)),
            softwareEnforced,
            hardwareEnforced,
        )
        // X509Certificate.getExtensionValue returns the extnValue OCTET STRING itself
        return DEROctetString(description.encoded).encoded
    }

    @Test
    fun parsesKeyDescriptionFields() {
        val applicationId = sequence(
            DERSet(sequence(DEROctetString("dev.eudisovereign.icaowallet".toByteArray()), ASN1Integer(1))),
            DERSet(DEROctetString(signerDigest)),
        )
        val softwareEnforced = sequence(DERTaggedObject(true, 709, DEROctetString(applicationId.encoded)))
        val rootOfTrust = sequence(DEROctetString(ByteArray(32)), ASN1Boolean.TRUE, ASN1Enumerated(0))
        val hardwareEnforced = sequence(
            DERTaggedObject(true, 1, DERSet(ASN1Integer(2))),
            DERTaggedObject(true, 704, rootOfTrust),
        )

        val parsed = Attestation.parseKeyDescription(keyDescription(softwareEnforced, hardwareEnforced))

        assertEquals(300, parsed.attestationVersion)
        assertEquals(2, parsed.attestationSecurityLevel)
        assertEquals(1, parsed.keyMintSecurityLevel)
        assertArrayEquals(challenge, parsed.attestationChallenge)
        val app = requireNotNull(parsed.applicationId)
        assertEquals(listOf("dev.eudisovereign.icaowallet" to 1L), app.packages)
        assertArrayEquals(signerDigest, app.signatureDigests.single())
        val root = requireNotNull(parsed.rootOfTrust)
        assertTrue(root.deviceLocked)
        assertEquals(0, root.verifiedBootState)
    }

    @Test
    fun missingOptionalListsYieldNulls() {
        val parsed = Attestation.parseKeyDescription(keyDescription(sequence(), sequence()))
        assertNull(parsed.applicationId)
        assertNull(parsed.rootOfTrust)
    }

    @Test
    fun malformedExtensionIsRejected() {
        assertThrows(IllegalArgumentException::class.java) {
            Attestation.parseKeyDescription(DEROctetString(sequence(ASN1Integer(3)).encoded).encoded)
        }
        assertThrows(IllegalArgumentException::class.java) { Attestation.parseKeyDescription(byteArrayOf(0x04, 0x05)) }
    }

    private fun certificate(subject: String, notAfterMillis: Long): ByteArray {
        val keyPair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }
            .generateKeyPair()
        val algorithm = AlgorithmIdentifier(X9ObjectIdentifiers.ecdsa_with_SHA256)
        val tbs = V3TBSCertificateGenerator().apply {
            setSerialNumber(ASN1Integer(1))
            setSignature(algorithm)
            setIssuer(X500Name("CN=Issuer"))
            setSubject(X500Name("CN=$subject"))
            setStartDate(Time(Date(0)))
            setEndDate(Time(Date(notAfterMillis)))
            setSubjectPublicKeyInfo(SubjectPublicKeyInfo.getInstance(keyPair.public.encoded))
        }.generateTBSCertificate()
        val signature = Signature.getInstance("SHA256withECDSA").run {
            initSign(keyPair.private)
            update(tbs.encoded)
            sign()
        }
        return sequence(tbs, algorithm, DERBitString(signature)).encoded
    }

    @Test
    fun chainExpiryIsTheEarliestNotAfter() {
        val leafEnd = Instant.parse("2030-01-01T00:00:00Z").toEpochMilli()
        val intermediateEnd = Instant.parse("2026-11-20T08:30:00Z").toEpochMilli()
        val rootEnd = Instant.parse("2040-06-01T00:00:00Z").toEpochMilli()
        val chain = listOf(
            certificate("Leaf", leafEnd),
            certificate("Intermediate", intermediateEnd),
            certificate("Root", rootEnd),
        )

        val expiry = requireNotNull(Attestation.chainExpiry(chain))

        assertEquals(1, expiry.index)
        assertEquals("CN=Intermediate", expiry.subject)
        assertEquals(intermediateEnd, expiry.notAfterMillis)
        assertFalse(expiry.isExpired(intermediateEnd))
        assertTrue(expiry.isExpired(intermediateEnd + 1))
        assertEquals(intermediateEnd, Attestation.summarize(chain).expiry?.notAfterMillis)
    }

    @Test
    fun chainExpiryOfAnEmptyOrBrokenChain() {
        assertNull(Attestation.chainExpiry(emptyList()))
        assertThrows(IllegalArgumentException::class.java) { Attestation.chainExpiry(listOf(byteArrayOf(0x30, 0x00))) }
    }

    @Test
    fun namesFollowTheKeyDescriptionEnumerations() {
        assertEquals("Software", Attestation.securityLevelName(0))
        assertEquals("TrustedEnvironment", Attestation.securityLevelName(1))
        assertEquals("StrongBox", Attestation.securityLevelName(2))
        assertEquals("Verified", Attestation.verifiedBootStateName(0))
        assertEquals("Failed", Attestation.verifiedBootStateName(3))
    }
}
