package dev.eudisovereign.icaowallet.nfc

import dev.eudisovereign.icaowallet.crypto.Codec
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.PublicKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import org.jmrtd.lds.ActiveAuthenticationInfo
import org.jmrtd.lds.ChipAuthenticationInfo
import org.jmrtd.lds.ChipAuthenticationPublicKeyInfo
import org.jmrtd.lds.SecurityInfo
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

class DocumentSecurityTest {

    private fun ecKey(curve: String = "secp256r1"): PublicKey =
        KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec(curve)) }.generateKeyPair().public

    private fun rsaKey(): PublicKey =
        KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair().public

    @Test
    fun parsesPublicSpecimenDnie3Sod() {
        val sodBytes = javaClass.getResourceAsStream("/external/SOD_ESPECIMEN.der")?.use { it.readBytes() }
        assumeTrue("SOD_ESPECIMEN.der is not available", sodBytes != null)

        val parsed = DocumentSecurity.parseSod(sodBytes!!)

        assertEquals("SHA-1", parsed.summary.ldsHashAlgorithm)
        assertEquals(listOf(1, 2, 3, 7, 11, 13, 14), parsed.summary.dataGroups)
        assertTrue(parsed.dataGroupHashes.values.all { it.size == 20 })
        val subject = parsed.summary.dsSubject
        assertNotNull(subject)
        assertTrue(subject!!, subject.split(",").contains("CN=DS n-eID SPAIN 2"))
        assertTrue(parsed.summary.dsIssuer!!.contains("CN=CSCA SPAIN"))
        assertNotNull(parsed.summary.dsSerialHex)
        assertTrue(parsed.summary.dsNotBeforeMillis!! < parsed.summary.dsNotAfterMillis!!)
        assertEquals("SHA-256", parsed.summary.signerDigestAlgorithm)
    }

    @Test
    fun rejectsGarbageSod() {
        assertThrows(IllegalArgumentException::class.java) { DocumentSecurity.parseSod(byteArrayOf(0x77, 0x03, 1, 2, 3)) }
    }

    @Test
    fun hashComparisonUsesTheGivenAlgorithm() {
        val abc = "abc".toByteArray()
        val sha1Abc = Codec.unhex("a9993e364706816aba3e25717850c26c9cd0d89d")
        assertTrue(DocumentSecurity.hashMatches("SHA-1", abc, sha1Abc))
        assertFalse(DocumentSecurity.hashMatches("SHA-256", abc, sha1Abc))
        assertFalse(DocumentSecurity.hashMatches("SHA-1", "abd".toByteArray(), sha1Abc))
        assertThrows(IllegalArgumentException::class.java) { DocumentSecurity.hashMatches("NOPE-1", abc, sha1Abc) }
    }

    @Test
    fun infersChipAuthenticationOidLikeJmrtd() {
        assertEquals(SecurityInfo.ID_CA_ECDH_3DES_CBC_CBC, DocumentSecurity.inferChipAuthenticationOid(SecurityInfo.ID_PK_ECDH))
        assertEquals(SecurityInfo.ID_CA_DH_3DES_CBC_CBC, DocumentSecurity.inferChipAuthenticationOid(SecurityInfo.ID_PK_DH))
        assertNull(DocumentSecurity.inferChipAuthenticationOid("1.2.3"))
        assertEquals("0.4.0.127.0.7.2.2.1.2", SecurityInfo.ID_PK_ECDH)
    }

    @Test
    fun selectsChipAuthenticationKeyByKeyId() {
        val key1 = ecKey()
        val key2 = ecKey()
        val infos = listOf<SecurityInfo>(
            ChipAuthenticationPublicKeyInfo(key1, BigInteger.ONE),
            ChipAuthenticationPublicKeyInfo(key2, BigInteger.TWO),
            ChipAuthenticationInfo(SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_128, ChipAuthenticationInfo.VERSION_1, BigInteger.TWO),
        )
        val parameters = DocumentSecurity.chipAuthenticationParameters(infos)!!
        assertEquals(BigInteger.TWO, parameters.keyId)
        assertEquals(SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_128, parameters.protocolOid)
        assertFalse(parameters.protocolOidInferred)
        assertEquals(SecurityInfo.ID_PK_ECDH, parameters.publicKeyOid)
        assertEquals((key2 as ECPublicKey).w, (parameters.publicKey as ECPublicKey).w)
        assertEquals("ECDH AES-128", DocumentSecurity.describeChipAuthenticationOid(parameters.protocolOid))
    }

    @Test
    fun prefersStrongestChipAuthenticationCipher() {
        val key = ecKey()
        val tripleDesAndAes128 = listOf<SecurityInfo>(
            ChipAuthenticationPublicKeyInfo(key),
            ChipAuthenticationInfo(SecurityInfo.ID_CA_ECDH_3DES_CBC_CBC, ChipAuthenticationInfo.VERSION_1),
            ChipAuthenticationInfo(SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_128, ChipAuthenticationInfo.VERSION_1),
        )
        assertEquals(
            SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_128,
            DocumentSecurity.chipAuthenticationParameters(tripleDesAndAes128)!!.protocolOid,
        )

        val aes128AndAes256 = listOf<SecurityInfo>(
            ChipAuthenticationPublicKeyInfo(key),
            ChipAuthenticationInfo(SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_128, ChipAuthenticationInfo.VERSION_1),
            ChipAuthenticationInfo(SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_256, ChipAuthenticationInfo.VERSION_1),
        )
        assertEquals(
            SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_256,
            DocumentSecurity.chipAuthenticationParameters(aes128AndAes256)!!.protocolOid,
        )
    }

    @Test
    fun infersProtocolWhenDg14HasOnlyThePublicKey() {
        val parameters = DocumentSecurity.chipAuthenticationParameters(
            listOf(ChipAuthenticationPublicKeyInfo(ecKey())),
        )!!
        assertTrue(parameters.protocolOidInferred)
        assertEquals(SecurityInfo.ID_CA_ECDH_3DES_CBC_CBC, parameters.protocolOid)
        assertNull(DocumentSecurity.chipAuthenticationParameters(listOf(ActiveAuthenticationInfo(ActiveAuthenticationInfo.ECDSA_PLAIN_SHA256_OID))))
    }

    @Test
    fun rejectsUnmatchedChipAuthenticationInfo() {
        val infos = listOf<SecurityInfo>(
            ChipAuthenticationPublicKeyInfo(ecKey(), BigInteger.ONE),
            ChipAuthenticationPublicKeyInfo(ecKey(), BigInteger.TWO),
            ChipAuthenticationInfo(SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_128, ChipAuthenticationInfo.VERSION_1, BigInteger.TEN),
        )
        assertThrows(IllegalArgumentException::class.java) { DocumentSecurity.chipAuthenticationParameters(infos) }
    }

    @Test
    fun activeAuthenticationAlgorithmsAndLengths() {
        val rsa = rsaKey()
        val rsaAlgorithms = DocumentSecurity.aaAlgorithms(rsa, null)
        assertEquals("named by the ISO/IEC 9796-2 trailer", rsaAlgorithms.digest)
        assertEquals("RSA ISO/IEC 9796-2 scheme 1", rsaAlgorithms.signature)
        assertFalse(rsaAlgorithms.digestAssumed)
        assertEquals(256, DocumentSecurity.expectedAaResponseLength(rsa))
        assertEquals("RSA-2048", DocumentSecurity.describeKey(rsa))

        val ec = ecKey()
        val signalled = DocumentSecurity.aaAlgorithms(ec, ActiveAuthenticationInfo.ECDSA_PLAIN_SHA384_OID)
        assertEquals("SHA-384", signalled.digest)
        assertFalse(signalled.digestAssumed)
        val assumed = DocumentSecurity.aaAlgorithms(ec, null)
        assertEquals("SHA-256", assumed.digest)
        assertTrue(assumed.digestAssumed)
        assertEquals(64, DocumentSecurity.expectedAaResponseLength(ec))
        assertEquals("EC secp256r1", DocumentSecurity.describeKey(ec))
        assertEquals("EC secp384r1", DocumentSecurity.describeKey(ecKey("secp384r1")))

        val aaInfo = listOf<SecurityInfo>(ActiveAuthenticationInfo(ActiveAuthenticationInfo.ECDSA_PLAIN_SHA256_OID))
        assertEquals(ActiveAuthenticationInfo.ECDSA_PLAIN_SHA256_OID, DocumentSecurity.activeAuthenticationSignatureOid(aaInfo))
    }

    @Test
    fun describesPaceProtocol() {
        assertEquals("ECDH-GM AES-128", DocumentSecurity.describePaceOid(SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_128))
        assertEquals("1.2.3", DocumentSecurity.describePaceOid("1.2.3"))
    }
}
