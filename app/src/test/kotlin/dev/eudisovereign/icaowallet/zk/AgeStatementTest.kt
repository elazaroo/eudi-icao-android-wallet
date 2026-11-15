package dev.eudisovereign.icaowallet.zk

import java.math.BigInteger
import java.security.MessageDigest
import java.time.Instant
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class AgeStatementTest {

    @Test
    fun challengeIsTheFirst31BytesOfTheLabelledHash() {
        val nonce = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        val origin = "https://verifier.example"
        val hash = MessageDigest.getInstance("SHA-256")
            .digest("eudi-icao-age-proof-v1\n$nonce\n$origin".toByteArray(Charsets.UTF_8))
        val expected = hash.copyOf(31).fold(BigInteger.ZERO) { acc, byte -> acc.shiftLeft(8).or(BigInteger.valueOf((byte.toInt() and 0xFF).toLong())) }
        val challenge = AgeStatement.challenge(nonce, origin)
        assertEquals(expected, challenge)
        assertTrue(challenge.bitLength() <= 248)
        assertTrue(challenge < AgeStatement.FIELD_ORDER)
    }

    @Test
    fun challengeDependsOnNonceAndOrigin() {
        val base = AgeStatement.challenge("nonce", "https://a.example")
        assertTrue(base != AgeStatement.challenge("nonce2", "https://a.example"))
        assertTrue(base != AgeStatement.challenge("nonce", "https://b.example"))
        assertTrue(base != AgeStatement.challenge("nonce\nhttps://a.example", ""))
    }

    @Test
    fun dateNumberUsesTheUtcCalendarDate() {
        assertEquals(20261115, AgeStatement.dateNumber(Instant.parse("2026-11-15T23:59:59.999Z").toEpochMilli()))
        assertEquals(20261116, AgeStatement.dateNumber(Instant.parse("2026-11-16T00:00:00Z").toEpochMilli()))
        assertEquals(20280229, AgeStatement.dateNumber(Instant.parse("2028-02-29T12:00:00Z").toEpochMilli()))
    }

    @Test
    fun limbsRoundTripAndRejectOversizedValues() {
        val value = BigInteger.ONE.shiftLeft(2048).subtract(BigInteger.valueOf(12345))
        val limbs = AgeStatement.toLimbs(value)
        assertEquals(AgeStatement.LIMBS, limbs.size)
        assertTrue(limbs.all { it.bitLength() <= AgeStatement.LIMB_BITS })
        assertEquals(value, AgeStatement.fromLimbs(limbs))
        assertEquals(BigInteger.valueOf(5), AgeStatement.toLimbs(BigInteger.valueOf(5))[0])
        assertThrows(IllegalArgumentException::class.java) { AgeStatement.toLimbs(BigInteger.ONE.shiftLeft(121 * 17)) }
        assertThrows(IllegalArgumentException::class.java) { AgeStatement.toLimbs(BigInteger.ONE.negate()) }
    }

    @Test
    fun publicSignalsAreLimbsDateThresholdAndChallenge() {
        val modulus = BigInteger.ONE.shiftLeft(2047).add(BigInteger.valueOf(99))
        val signals = AgeStatement.publicSignals(modulus, 20261115, 18, BigInteger.valueOf(7))
        assertEquals(AgeStatement.PUBLIC_SIGNAL_COUNT, signals.size)
        assertEquals(modulusLimbs(modulus), signals.take(AgeStatement.LIMBS))
        assertEquals(listOf("20261115", "18", "7"), signals.takeLast(3))
    }
}
