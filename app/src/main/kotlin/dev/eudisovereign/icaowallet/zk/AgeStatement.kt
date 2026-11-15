package dev.eudisovereign.icaowallet.zk

import dev.eudisovereign.icaowallet.crypto.Codec
import java.math.BigInteger
import java.time.Instant
import java.time.ZoneOffset

/** Shape of circuits/age_proof.circom of the web verifier; mirrors src/zk/statement.ts. */
object AgeStatement {
    const val LIMB_BITS = 121
    const val LIMBS = 17
    const val SIGNED_ATTRS_BLOCKS = 3
    const val ECONTENT_BLOCKS = 4
    const val DG1_BLOCKS = 2
    const val RSA_MODULUS_BITS = 2048
    val RSA_EXPONENT: BigInteger = BigInteger.valueOf(65537)
    const val AGE_THRESHOLD = 18

    /** Modulus limbs, currentDate, ageThreshold, challenge, in the order the circuit declares them. */
    const val PUBLIC_SIGNAL_COUNT = LIMBS + 3

    /** BN254 scalar field order. */
    val FIELD_ORDER = BigInteger("21888242871839275222246405745257275088548364400416034343698204186575808495617")

    private const val CHALLENGE_LABEL = "eudi-icao-age-proof-v1"
    private const val CHALLENGE_BYTES = 31

    fun toLimbs(value: BigInteger, bits: Int = LIMB_BITS, count: Int = LIMBS): List<BigInteger> {
        if (value.signum() < 0 || value.bitLength() > bits * count) {
            throw IllegalArgumentException("value does not fit in $count limbs of $bits bits")
        }
        val mask = BigInteger.ONE.shiftLeft(bits).subtract(BigInteger.ONE)
        return List(count) { index -> value.shiftRight(index * bits).and(mask) }
    }

    fun fromLimbs(limbs: List<BigInteger>, bits: Int = LIMB_BITS): BigInteger =
        limbs.foldIndexed(BigInteger.ZERO) { index, sum, limb -> sum.add(limb.shiftLeft(index * bits)) }

    /** Spec 8.3: SHA-256 of label, nonce and origin, first 31 bytes as a big-endian integer. */
    fun challenge(nonce: String, origin: String): BigInteger {
        val hash = Codec.sha256("$CHALLENGE_LABEL\n$nonce\n$origin".toByteArray(Charsets.UTF_8))
        return BigInteger(1, hash.copyOf(CHALLENGE_BYTES))
    }

    /** UTC calendar date as the YYYYMMDD integer the circuit compares. */
    fun dateNumber(epochMillis: Long): Int {
        val date = Instant.ofEpochMilli(epochMillis).atOffset(ZoneOffset.UTC).toLocalDate()
        return date.year * 10000 + date.monthValue * 100 + date.dayOfMonth
    }

    fun publicSignals(modulus: BigInteger, currentDate: Int, ageThreshold: Int, challenge: BigInteger): List<String> =
        toLimbs(modulus).map(BigInteger::toString) +
            listOf(currentDate.toString(), ageThreshold.toString(), challenge.toString())
}
