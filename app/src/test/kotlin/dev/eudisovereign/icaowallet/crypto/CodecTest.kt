package dev.eudisovereign.icaowallet.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class CodecTest {

    private val bytes = byteArrayOf(0x00, 0x0F, 0xF0.toByte(), 0xFB.toByte(), 0xFF.toByte())

    @Test
    fun hexRoundTrip() {
        assertEquals("000ff0fbff", Codec.hex(bytes))
        assertArrayEquals(bytes, Codec.unhex("000FF0FBFF"))
        assertThrows(IllegalArgumentException::class.java) { Codec.unhex("abc") }
        assertThrows(IllegalArgumentException::class.java) { Codec.unhex("zz") }
    }

    @Test
    fun base64VariantsFollowRfc4648() {
        assertEquals("AA/w+/8=", Codec.b64(bytes))
        assertEquals("AA_w-_8", Codec.b64url(bytes))
        assertArrayEquals(bytes, Codec.unb64("AA/w+/8="))
        assertArrayEquals(bytes, Codec.unb64url("AA_w-_8"))
        assertThrows(IllegalArgumentException::class.java) { Codec.unb64url("AA_w-_8=") }
        assertThrows(IllegalArgumentException::class.java) { Codec.unb64("AA_w-_8=") }
    }

    // FIPS 180-2 Appendix A.1 and B.1
    @Test
    fun digestsOfAbc() {
        val abc = "abc".toByteArray(Charsets.US_ASCII)
        assertEquals("a9993e364706816aba3e25717850c26c9cd0d89d", Codec.hex(Codec.sha1(abc)))
        assertEquals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", Codec.hex(Codec.sha256(abc)))
    }
}
