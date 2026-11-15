package dev.eudisovereign.icaowallet.crypto

import java.math.BigInteger
import org.bouncycastle.asn1.x9.ECNamedCurveTable
import org.bouncycastle.crypto.InvalidCipherTextException
import org.bouncycastle.crypto.hpke.HPKE

class HpkeCiphertext(val enc: ByteArray, val ct: ByteArray)

class HpkeException(message: String, cause: Throwable? = null) : Exception(message, cause)

object Hpke {

    private val p256 = ECNamedCurveTable.getByName("P-256")

    // RFC 9180 7: KEM 0x0010 DHKEM(P-256, HKDF-SHA256), KDF 0x0001 HKDF-SHA256, AEAD 0x0001 AES-128-GCM
    private fun suite() = HPKE(HPKE.mode_base, HPKE.kem_P256_SHA256, HPKE.kdf_HKDF_SHA256, HPKE.aead_AES_GCM128)

    fun isValidP256Point(encoded: ByteArray): Boolean {
        if (encoded.size != 65 || encoded[0] != 0x04.toByte()) return false
        return try {
            val point = p256.curve.decodePoint(encoded)
            !point.isInfinity && point.isValid
        } catch (e: IllegalArgumentException) {
            false
        }
    }

    fun seal(recipientPublicKey65: ByteArray, info: ByteArray, aad: ByteArray, plaintext: ByteArray): HpkeCiphertext {
        if (!isValidP256Point(recipientPublicKey65)) {
            throw HpkeException("Recipient key is not an uncompressed P-256 point")
        }
        val hpke = suite()
        val context = try {
            hpke.setupBaseS(hpke.deserializePublicKey(recipientPublicKey65), info)
        } catch (e: RuntimeException) {
            throw HpkeException("HPKE encapsulation failed", e)
        }
        val ct = try {
            context.seal(aad, plaintext)
        } catch (e: InvalidCipherTextException) {
            throw HpkeException("HPKE seal failed", e)
        }
        return HpkeCiphertext(context.encapsulation, ct)
    }

    fun open(recipientPrivateKey: ByteArray, enc: ByteArray, info: ByteArray, aad: ByteArray, ct: ByteArray): ByteArray {
        val d = BigInteger(1, recipientPrivateKey)
        if (recipientPrivateKey.size != 32 || d.signum() <= 0 || d >= p256.n) {
            throw HpkeException("Recipient private key is not a valid P-256 scalar")
        }
        if (!isValidP256Point(enc)) throw HpkeException("Encapsulated key is not an uncompressed P-256 point")
        val publicKey = p256.g.multiply(d).normalize().getEncoded(false)
        val hpke = suite()
        return try {
            hpke.setupBaseR(enc, hpke.deserializePrivateKey(recipientPrivateKey, publicKey), info).open(aad, ct)
        } catch (e: InvalidCipherTextException) {
            throw HpkeException("HPKE open failed: authentication tag mismatch", e)
        } catch (e: RuntimeException) {
            throw HpkeException("HPKE open failed", e)
        }
    }
}
