package dev.eudisovereign.icaowallet.nfc

import dev.eudisovereign.icaowallet.crypto.Codec
import java.io.ByteArrayInputStream
import java.io.IOException
import java.math.BigInteger
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException
import java.security.PublicKey
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.ECParameterSpec
import javax.crypto.interfaces.DHPublicKey
import javax.security.auth.x500.X500Principal
import kotlinx.serialization.Serializable
import org.bouncycastle.asn1.x9.ECNamedCurveTable
import org.jmrtd.lds.ActiveAuthenticationInfo
import org.jmrtd.lds.ChipAuthenticationInfo
import org.jmrtd.lds.ChipAuthenticationPublicKeyInfo
import org.jmrtd.lds.PACEInfo
import org.jmrtd.lds.SODFile
import org.jmrtd.lds.SecurityInfo

@Serializable
class SodSummary(
    val ldsHashAlgorithm: String,
    val dataGroups: List<Int>,
    val signerDigestAlgorithm: String?,
    val signatureAlgorithm: String?,
    val ldsVersion: String?,
    val dsSubject: String?,
    val dsIssuer: String?,
    val dsSerialHex: String?,
    val dsNotBeforeMillis: Long?,
    val dsNotAfterMillis: Long?,
)

class ParsedSod(val summary: SodSummary, val dataGroupHashes: Map<Int, ByteArray>)

class ChipAuthenticationParameters(
    val keyId: BigInteger?,
    val protocolOid: String,
    val protocolOidInferred: Boolean,
    val publicKeyOid: String,
    val publicKey: PublicKey,
)

class AaAlgorithms(val digest: String, val signature: String, val digestAssumed: Boolean)

object DocumentSecurity {

    private val preferredCurves = listOf(
        "brainpoolP256r1", "brainpoolP384r1", "brainpoolP512r1", "brainpoolP320r1", "brainpoolP224r1",
        "brainpoolP192r1", "secp256r1", "secp384r1", "secp521r1", "secp224r1", "secp192r1",
    )

    fun parseSod(sodBytes: ByteArray): ParsedSod {
        val sod = try {
            SODFile(ByteArrayInputStream(sodBytes))
        } catch (e: IOException) {
            throw IllegalArgumentException("EF.SOD cannot be parsed: ${e.message}", e)
        } catch (e: RuntimeException) {
            throw IllegalArgumentException("EF.SOD cannot be parsed: ${e.message}", e)
        }
        // ICAO 9303-10 4.6.2: the data group hashes use LDSSecurityObject.hashAlgorithm, not the CMS digest
        val ldsHash = sod.digestAlgorithm
            ?: throw IllegalArgumentException("EF.SOD uses an unknown LDS hash algorithm")
        val hashes = sod.dataGroupHashes.toSortedMap()
        val ds = sod.docSigningCertificate
        val summary = SodSummary(
            ldsHashAlgorithm = ldsHash,
            dataGroups = hashes.keys.toList(),
            signerDigestAlgorithm = runCatching { sod.signerInfoDigestAlgorithm }.getOrNull(),
            signatureAlgorithm = runCatching { sod.digestEncryptionAlgorithm }.getOrNull(),
            ldsVersion = runCatching { sod.ldsVersion }.getOrNull(),
            dsSubject = ds?.subjectX500Principal?.getName(X500Principal.RFC2253),
            dsIssuer = ds?.issuerX500Principal?.getName(X500Principal.RFC2253),
            dsSerialHex = ds?.serialNumber?.toString(16),
            dsNotBeforeMillis = ds?.notBefore?.time,
            dsNotAfterMillis = ds?.notAfter?.time,
        )
        return ParsedSod(summary, hashes)
    }

    fun hashMatches(algorithm: String, fileBytes: ByteArray, expected: ByteArray): Boolean {
        val actual = try {
            Codec.digest(algorithm, fileBytes)
        } catch (e: NoSuchAlgorithmException) {
            throw IllegalArgumentException("Unsupported LDS hash algorithm $algorithm", e)
        }
        return MessageDigest.isEqual(actual, expected)
    }

    /** Same best-effort inference as JMRTD EACCAProtocol when DG14 carries no ChipAuthenticationInfo. */
    fun inferChipAuthenticationOid(publicKeyOid: String): String? = when (publicKeyOid) {
        SecurityInfo.ID_PK_ECDH -> SecurityInfo.ID_CA_ECDH_3DES_CBC_CBC
        SecurityInfo.ID_PK_DH -> SecurityInfo.ID_CA_DH_3DES_CBC_CBC
        else -> null
    }

    fun chipAuthenticationParameters(dg14Infos: Collection<SecurityInfo>): ChipAuthenticationParameters? {
        val keyInfos = dg14Infos.filterIsInstance<ChipAuthenticationPublicKeyInfo>()
            .sortedBy { it.keyId ?: BigInteger.ZERO }
        if (keyInfos.isEmpty()) return null
        // Strongest offered secure messaging first: AES before 3DES, then the longer key
        val caInfos = dg14Infos.filterIsInstance<ChipAuthenticationInfo>()
            .sortedWith(
                compareBy<ChipAuthenticationInfo> { it.keyId ?: BigInteger.ZERO }
                    .thenBy { caCipherRank(it.objectIdentifier) }
                    .thenByDescending { caKeyLength(it.objectIdentifier) }
                    .thenBy { it.objectIdentifier },
            )
        // ICAO 9303-11 ChipAuthenticationInfo: keyId selects the public key when the chip holds several
        for (caInfo in caInfos) {
            val keyInfo = keyInfos.firstOrNull { it.keyId == caInfo.keyId }
                ?: keyInfos.singleOrNull()?.takeIf { caInfos.size == 1 }
                ?: continue
            return ChipAuthenticationParameters(
                keyId = keyInfo.keyId ?: caInfo.keyId,
                protocolOid = caInfo.objectIdentifier,
                protocolOidInferred = false,
                publicKeyOid = keyInfo.objectIdentifier,
                publicKey = keyInfo.subjectPublicKey,
            )
        }
        if (caInfos.isNotEmpty()) {
            throw IllegalArgumentException("EF.DG14 ChipAuthenticationInfo does not match any Chip Authentication key")
        }
        val keyInfo = keyInfos.first()
        val inferred = inferChipAuthenticationOid(keyInfo.objectIdentifier)
            ?: throw IllegalArgumentException("Unsupported Chip Authentication key type ${keyInfo.objectIdentifier}")
        return ChipAuthenticationParameters(keyInfo.keyId, inferred, true, keyInfo.objectIdentifier, keyInfo.subjectPublicKey)
    }

    // ChipAuthenticationInfo.toCipherAlgorithm and toKeyLength throw NumberFormatException for unknown OIDs.
    private fun caCipherRank(oid: String): Int = try {
        when (ChipAuthenticationInfo.toCipherAlgorithm(oid)) {
            "AES" -> 0
            "DESede" -> 1
            else -> 2
        }
    } catch (e: RuntimeException) {
        2
    }

    private fun caKeyLength(oid: String): Int = try {
        ChipAuthenticationInfo.toKeyLength(oid)
    } catch (e: RuntimeException) {
        0
    }

    fun describeChipAuthenticationOid(oid: String): String = try {
        val agreement = ChipAuthenticationInfo.toKeyAgreementAlgorithm(oid)
        val cipher = ChipAuthenticationInfo.toCipherAlgorithm(oid)
        val bits = ChipAuthenticationInfo.toKeyLength(oid)
        "$agreement $cipher-$bits"
    } catch (e: RuntimeException) {
        oid
    }

    fun describePaceOid(oid: String): String = try {
        val agreement = PACEInfo.toKeyAgreementAlgorithm(oid)
        val mapping = PACEInfo.toMappingType(oid)
        val cipher = PACEInfo.toCipherAlgorithm(oid)
        val bits = PACEInfo.toKeyLength(oid)
        "$agreement-$mapping $cipher-$bits"
    } catch (e: RuntimeException) {
        oid
    }

    fun describeKey(key: PublicKey): String = when (key) {
        is ECPublicKey -> "EC " + (curveName(key.params) ?: "explicit ${key.params.curve.field.fieldSize}-bit curve")
        is RSAPublicKey -> "RSA-${key.modulus.bitLength()}"
        is DHPublicKey -> "DH-${key.params.p.bitLength()}"
        else -> key.algorithm
    }

    fun curveName(params: ECParameterSpec): String? = preferredCurves.firstOrNull { name ->
        val candidate = ECNamedCurveTable.getByName(name) ?: return@firstOrNull false
        val g = candidate.g.normalize()
        candidate.n == params.order &&
            g.affineXCoord.toBigInteger() == params.generator.affineX &&
            g.affineYCoord.toBigInteger() == params.generator.affineY
    }

    /**
     * Digest and signature names for INTERNAL AUTHENTICATE. JMRTD does not interpret them; they document what the
     * verifier will check (spec section 5.3).
     */
    fun aaAlgorithms(key: PublicKey, aaSignatureOid: String?): AaAlgorithms = when (key) {
        // ICAO 9303-11 6.1: RSA uses ISO/IEC 9796-2 scheme 1; the trailer of the recovered message names the digest,
        // and the wallet does not recover it
        is RSAPublicKey -> AaAlgorithms(
            digest = "named by the ISO/IEC 9796-2 trailer",
            signature = "RSA ISO/IEC 9796-2 scheme 1",
            digestAssumed = false,
        )
        is ECPublicKey -> {
            val fromInfo = aaSignatureOid?.let(::ecdsaPlainDigest)
            if (fromInfo != null) {
                AaAlgorithms(fromInfo, fromInfo.replace("-", "") + "withPLAIN-ECDSA", digestAssumed = false)
            } else {
                val digest = digestForFieldSize(key.params.curve.field.fieldSize)
                AaAlgorithms(digest, digest.replace("-", "") + "withPLAIN-ECDSA", digestAssumed = true)
            }
        }
        else -> throw IllegalArgumentException("Unsupported Active Authentication key ${key.algorithm}")
    }

    fun expectedAaResponseLength(key: PublicKey): Int = when (key) {
        is RSAPublicKey -> (key.modulus.bitLength() + 7) / 8
        is ECPublicKey -> 2 * ((key.params.order.bitLength() + 7) / 8)
        else -> throw IllegalArgumentException("Unsupported Active Authentication key ${key.algorithm}")
    }

    fun activeAuthenticationSignatureOid(dg14Infos: Collection<SecurityInfo>): String? =
        dg14Infos.filterIsInstance<ActiveAuthenticationInfo>().firstOrNull()?.signatureAlgorithmOID

    private fun ecdsaPlainDigest(oid: String): String? = when (oid) {
        ActiveAuthenticationInfo.ECDSA_PLAIN_SHA1_OID -> "SHA-1"
        ActiveAuthenticationInfo.ECDSA_PLAIN_SHA224_OID -> "SHA-224"
        ActiveAuthenticationInfo.ECDSA_PLAIN_SHA256_OID -> "SHA-256"
        ActiveAuthenticationInfo.ECDSA_PLAIN_SHA384_OID -> "SHA-384"
        ActiveAuthenticationInfo.ECDSA_PLAIN_SHA512_OID -> "SHA-512"
        else -> null
    }

    private fun digestForFieldSize(bits: Int): String = when {
        bits <= 160 -> "SHA-1"
        bits <= 224 -> "SHA-224"
        bits <= 256 -> "SHA-256"
        bits <= 384 -> "SHA-384"
        else -> "SHA-512"
    }
}
