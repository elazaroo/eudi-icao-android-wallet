package dev.eudisovereign.icaowallet.protocol

import dev.eudisovereign.icaowallet.TestKeys
import dev.eudisovereign.icaowallet.crypto.Codec
import dev.eudisovereign.icaowallet.crypto.Hpke
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class SessionDescriptorTest {

    private val now = 1_763_000_000_000L
    private val nonceBytes = ByteArray(32) { (it * 7).toByte() }
    private val nonce = Codec.b64url(nonceBytes)
    private val ek = TestKeys.p256().publicPoint

    private fun descriptor(
        v: Int = 1,
        nonce: String = this.nonce,
        timestamp: Long = now,
        origin: String = "https://verifier.example",
        ek: String = Codec.b64url(this.ek),
        relay: String? = null,
        extra: String = "",
    ): String {
        val relayMember = relay?.let { ""","relay":"$it"""" } ?: ""
        return """{"v":$v,"peerId":"peer-123","nonce":"$nonce","timestamp":$timestamp,""" +
            """"origin":"$origin","ek":"$ek"$relayMember$extra}"""
    }

    @Test
    fun acceptsValidDescriptor() {
        val parsed = SessionDescriptor.parse(
            descriptor(relay = "https://relay.example/m/abc", extra = ""","future":{"x":1}"""),
            now + 60_000,
        )
        assertEquals("peer-123", parsed.peerId)
        assertEquals(nonce, parsed.nonce)
        assertArrayEquals(nonceBytes, parsed.nonceBytes)
        assertArrayEquals(ek, parsed.ek)
        assertEquals("https://verifier.example", parsed.origin)
        assertEquals("https://relay.example/m/abc", parsed.relay)
    }

    @Test
    fun acceptsLocalhostOriginWithPortAndNoRelay() {
        val parsed = SessionDescriptor.parse(descriptor(origin = "http://localhost:5173"), now)
        assertEquals("http://localhost:5173", parsed.origin)
        assertNull(parsed.relay)
    }

    @Test
    fun rejectsWrongVersion() {
        assertThrows(DescriptorException::class.java) { SessionDescriptor.parse(descriptor(v = 2), now) }
    }

    @Test
    fun rejectsShortNonce() {
        val short = Codec.b64url(ByteArray(31))
        assertThrows(DescriptorException::class.java) { SessionDescriptor.parse(descriptor(nonce = short), now) }
        val padded = Codec.b64(nonceBytes).replace('+', '-').replace('/', '_')
        assertTrue(padded.endsWith("="))
        assertThrows(DescriptorException::class.java) { SessionDescriptor.parse(descriptor(nonce = padded), now) }
    }

    @Test
    fun rejectsPointNotOnCurve() {
        val offCurve = ek.copyOf().also { it[64] = (it[64].toInt() xor 1).toByte() }
        check(!Hpke.isValidP256Point(offCurve))
        assertThrows(DescriptorException::class.java) {
            SessionDescriptor.parse(descriptor(ek = Codec.b64url(offCurve)), now)
        }
        val compressed = byteArrayOf(0x02) + ek.copyOfRange(1, 33)
        assertThrows(DescriptorException::class.java) {
            SessionDescriptor.parse(descriptor(ek = Codec.b64url(compressed)), now)
        }
    }

    @Test
    fun rejectsTimestampOutsideFiveMinutes() {
        val skew = SessionDescriptor.MAX_CLOCK_SKEW_MS
        SessionDescriptor.parse(descriptor(timestamp = now - skew), now)
        assertThrows(DescriptorException::class.java) { SessionDescriptor.parse(descriptor(timestamp = now - skew - 1), now) }
        assertThrows(DescriptorException::class.java) { SessionDescriptor.parse(descriptor(timestamp = now + skew + 1), now) }
    }

    @Test
    fun timestampCheckDoesNotOverflow() {
        // now - timestamp would be Long.MIN_VALUE, whose absolute value is still negative
        val farPast = now + Long.MIN_VALUE
        assertThrows(DescriptorException::class.java) { SessionDescriptor.parse(descriptor(timestamp = farPast), now) }
        assertThrows(DescriptorException::class.java) {
            SessionDescriptor.parse(descriptor(timestamp = Long.MAX_VALUE), now)
        }
    }

    @Test
    fun freshnessFollowsTheSameBounds() {
        val skew = SessionDescriptor.MAX_CLOCK_SKEW_MS
        val parsed = SessionDescriptor.parse(descriptor(timestamp = now), now)
        assertTrue(parsed.isFresh(now + skew))
        assertTrue(parsed.isFresh(now - skew))
        assertFalse(parsed.isFresh(now + skew + 1))
        assertFalse(parsed.isFresh(now - skew - 1))
    }

    @Test
    fun rejectsRelayWhoseResultUrlIsAmbiguous() {
        listOf("https://relay.example/m/abc?x=1", "https://relay.example/m/abc#f", "https://relay.example/m/abc/")
            .forEach { relay ->
                val e = assertThrows(relay, DescriptorException::class.java) {
                    SessionDescriptor.parse(descriptor(relay = relay), now)
                }
                assertEquals("relay must not carry a query, a fragment or a trailing slash", e.message)
            }
        assertEquals("https://relay.example", SessionDescriptor.parse(descriptor(relay = "https://relay.example"), now).relay)
    }

    @Test
    fun rejectsBadOrigin() {
        listOf("ftp://verifier.example", "https://verifier.example/path", "verifier.example", "https://user@host")
            .forEach { origin ->
                assertThrows(origin, DescriptorException::class.java) {
                    SessionDescriptor.parse(descriptor(origin = origin), now)
                }
            }
    }

    @Test
    fun descriptorWithoutRequestAsksForTheFullPresentation() {
        assertNull(SessionDescriptor.parse(descriptor(), now).request)
        assertNull(SessionDescriptor.parse(descriptor(extra = ""","request":null"""), now).request)
    }

    @Test
    fun ageOverEighteenRequestIsRecognised() {
        val parsed = SessionDescriptor.parse(
            descriptor(relay = "https://relay.example/m/abc", extra = ""","request":"age-over-18""""),
            now,
        )
        assertEquals(SessionRequest.AGE_OVER_18, parsed.request)
        assertEquals("https://verifier.example", parsed.origin)
        assertEquals(nonce, parsed.nonce)
    }

    @Test
    fun unknownRequestIsRefused() {
        listOf("age-over-21", "full", "").forEach { value ->
            val e = assertThrows(value, UnsupportedRequestException::class.java) {
                SessionDescriptor.parse(descriptor(extra = ""","request":"$value""""), now)
            }
            assertEquals(value, e.request)
            assertTrue(e.message!!, e.message!!.contains("\"$value\""))
        }
        assertThrows(DescriptorException::class.java) {
            SessionDescriptor.parse(descriptor(extra = ""","request":{"type":"age-over-18"}"""), now)
        }
    }

    @Test
    fun rejectsBadRelayAndMissingMembers() {
        assertThrows(DescriptorException::class.java) {
            SessionDescriptor.parse(descriptor(relay = "file:///etc/passwd"), now)
        }
        assertThrows(DescriptorException::class.java) {
            SessionDescriptor.parse("""{"v":1,"nonce":"$nonce","timestamp":$now}""", now)
        }
        assertThrows(DescriptorException::class.java) { SessionDescriptor.parse("not json", now) }
    }
}
