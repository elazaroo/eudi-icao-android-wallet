package dev.eudisovereign.icaowallet

import java.math.BigInteger
import java.security.SecureRandom
import org.bouncycastle.asn1.x9.ECNamedCurveTable

class P256TestKey(val privateScalar: ByteArray, val publicPoint: ByteArray)

object TestKeys {
    private val p256 = ECNamedCurveTable.getByName("P-256")
    private val random = SecureRandom()

    fun p256(): P256TestKey {
        var d: BigInteger
        do {
            d = BigInteger(256, random)
        } while (d.signum() == 0 || d >= p256.n)
        val scalar = d.toByteArray().let { raw ->
            when {
                raw.size == 32 -> raw
                raw.size > 32 -> raw.copyOfRange(raw.size - 32, raw.size)
                else -> ByteArray(32 - raw.size) + raw
            }
        }
        return P256TestKey(scalar, p256.g.multiply(d).normalize().getEncoded(false))
    }
}
