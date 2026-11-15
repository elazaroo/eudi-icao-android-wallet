package dev.eudisovereign.icaowallet.crypto

import dev.eudisovereign.icaowallet.TestKeys
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class HpkeTest {

    private val info = "eudi-icao-presentation-v1".toByteArray(Charsets.UTF_8)
    private val nonce = Codec.b64url(ByteArray(32) { it.toByte() })
    private val aad = nonce.toByteArray(Charsets.UTF_8)

    // RFC 9180 Appendix A.3.1 and A.3.1.1, sequence number 0
    @Test
    fun opensRfc9180AppendixA3Vector() {
        val skRm = Codec.unhex("f3ce7fdae57e1a310d87f1ebbde6f328be0a99cdbcadf4d6589cf29de4b8ffd2")
        val enc = Codec.unhex(
            "04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325" +
                "ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4",
        )
        val vectorInfo = Codec.unhex("4f6465206f6e2061204772656369616e2055726e")
        val vectorAad = Codec.unhex("436f756e742d30")
        val ct = Codec.unhex(
            "5ad590bb8baa577f8619db35a36311226a896e7342a6d836d8b7bcd2f20b6c7f" +
                "9076ac232e3ab2523f39513434",
        )
        val pt = Codec.unhex("4265617574792069732074727574682c20747275746820626561757479")

        assertArrayEquals(pt, Hpke.open(skRm, enc, vectorInfo, vectorAad, ct))
    }

    @Test
    fun rfc9180RecipientKeyIsAValidPoint() {
        val pkRm = Codec.unhex(
            "04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f70" +
                "6a826a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0",
        )
        assertTrue(Hpke.isValidP256Point(pkRm))
        val offCurve = pkRm.copyOf().also { it[64] = (it[64].toInt() xor 1).toByte() }
        assertFalse(Hpke.isValidP256Point(offCurve))
        assertFalse(Hpke.isValidP256Point(pkRm.copyOf(33)))
    }

    @Test
    fun sealOpenRoundTripWithProtocolInfoAndAad() {
        val key = TestKeys.p256()
        val plaintext = """{"v":1,"nonce":"$nonce"}""".toByteArray(Charsets.UTF_8)

        val sealed = Hpke.seal(key.publicPoint, info, aad, plaintext)

        assertEquals(65, sealed.enc.size)
        assertEquals(0x04, sealed.enc[0].toInt())
        assertEquals(plaintext.size + 16, sealed.ct.size)
        assertArrayEquals(plaintext, Hpke.open(key.privateScalar, sealed.enc, info, aad, sealed.ct))
    }

    @Test
    fun openRejectsTampering() {
        val key = TestKeys.p256()
        val plaintext = "presentation".toByteArray(Charsets.UTF_8)
        val sealed = Hpke.seal(key.publicPoint, info, aad, plaintext)

        val flippedCt = sealed.ct.copyOf().also { it[0] = (it[0].toInt() xor 0x01).toByte() }
        assertThrows(HpkeException::class.java) { Hpke.open(key.privateScalar, sealed.enc, info, aad, flippedCt) }

        val flippedTag = sealed.ct.copyOf().also { it[it.size - 1] = (it[it.size - 1].toInt() xor 0x80).toByte() }
        assertThrows(HpkeException::class.java) { Hpke.open(key.privateScalar, sealed.enc, info, aad, flippedTag) }

        val otherAad = "another-nonce".toByteArray(Charsets.UTF_8)
        assertThrows(HpkeException::class.java) { Hpke.open(key.privateScalar, sealed.enc, info, otherAad, sealed.ct) }

        val otherInfo = "eudi-icao-presentation-v2".toByteArray(Charsets.UTF_8)
        assertThrows(HpkeException::class.java) { Hpke.open(key.privateScalar, sealed.enc, otherInfo, aad, sealed.ct) }

        val otherEnc = TestKeys.p256().publicPoint
        assertThrows(HpkeException::class.java) { Hpke.open(key.privateScalar, otherEnc, info, aad, sealed.ct) }

        val otherKey = TestKeys.p256()
        assertThrows(HpkeException::class.java) { Hpke.open(otherKey.privateScalar, sealed.enc, info, aad, sealed.ct) }
    }

    @Test
    fun sealRejectsInvalidRecipientKey() {
        val point = TestKeys.p256().publicPoint
        val offCurve = point.copyOf().also { it[64] = (it[64].toInt() xor 1).toByte() }
        assertThrows(HpkeException::class.java) { Hpke.seal(offCurve, info, aad, byteArrayOf(1)) }
        assertThrows(HpkeException::class.java) { Hpke.seal(point.copyOf(64), info, aad, byteArrayOf(1)) }
    }
}
