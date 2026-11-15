package dev.eudisovereign.icaowallet.transport

import dev.eudisovereign.icaowallet.TestKeys
import dev.eudisovereign.icaowallet.crypto.Codec
import dev.eudisovereign.icaowallet.protocol.SessionDescriptor
import java.io.File
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.runBlocking
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Response
import okhttp3.ResponseBody.Companion.toResponseBody
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

class TransportFramingTest {

    @Test
    fun embeddedDataCannotCloseTheScriptElement() {
        val page = PeerJsPage.build("window.Peer = function () {};", "peer</script><script>alert(1)", listOf("a</script>b"))
        assertEquals(2, Regex("</script", RegexOption.IGNORE_CASE).findAll(page).count())
        assertTrue(page.contains("peer\\u003c/script\\u003e"))
    }

    @Test
    fun placeholderTextInsideDataIsNotSubstituted() {
        val page = PeerJsPage.build("window.Peer = function () {};", "a__PARTS__b", listOf("x__TARGET__y"))
        assertEquals(1, Regex(Regex.escape("var target = \"a__PARTS__b\";")).findAll(page).count())
        assertEquals(1, Regex(Regex.escape("var parts = [\"x__TARGET__y\"];")).findAll(page).count())
    }

    @Test
    fun libraryWithScriptBreakingSequenceIsRefused() {
        assertThrows(IllegalStateException::class.java) { PeerJsPage.build("var s = '</SCRIPT>';", "p", listOf("x")) }
        assertThrows(IllegalStateException::class.java) { PeerJsPage.build("var s = '<!--';", "p", listOf("x")) }
    }

    @Test
    fun bundledPeerjsBuildCanBeInlined() {
        val asset = File("src/main/assets/peerjs/peerjs.min.js")
        assumeTrue("peerjs asset not reachable from the test working directory", asset.isFile)
        val page = PeerJsPage.build(asset.readText(), "peer", listOf("""{"t":"part","i":0,"n":1,"d":"{}"}"""))
        assertEquals(2, Regex("</script", RegexOption.IGNORE_CASE).findAll(page).count())
        assertTrue(page.contains("serialization: \"raw\", reliable: true"))
    }

    @Test
    fun scriptSafeEscapesMarkupAndLineSeparators() {
        assertEquals("\"\\u003c\\u003e\\u0026\\u2028\\u2029\"", PeerJsPage.scriptSafe("\"<>&\u2028\u2029\""))
        assertFalse(PeerJsPage.scriptSafe("\"</script>\"").contains("<"))
    }

    @Test
    fun relayResultUrlAppendsPathSegmentAndWait() {
        assertEquals(
            "https://relay.example/m/abc/result?wait=25",
            RelayTransport.resultUrl("https://relay.example/m/abc".toHttpUrl()).toString(),
        )
        assertEquals(
            "http://192.168.1.10:8787/s/xyz/result?wait=25",
            RelayTransport.resultUrl("http://192.168.1.10:8787/s/xyz".toHttpUrl()).toString(),
        )
    }

    @Test
    fun immediateNoContentAnswersArePolledAtMostOncePerSecond() {
        val polls = AtomicInteger()
        val client = OkHttpClient.Builder()
            .addInterceptor { chain ->
                val request = chain.request()
                val code = if (request.method == "PUT") 200 else 204.also { polls.incrementAndGet() }
                Response.Builder()
                    .request(request)
                    .protocol(Protocol.HTTP_1_1)
                    .code(code)
                    .message("")
                    .body(ByteArray(0).toResponseBody())
                    .build()
            }
            .build()
        val descriptor = SessionDescriptor.parse(
            """{"v":1,"peerId":"p","nonce":"${Codec.b64url(ByteArray(32))}","timestamp":${System.currentTimeMillis()},""" +
                """"origin":"https://verifier.example","ek":"${Codec.b64url(TestKeys.p256().publicPoint)}",""" +
                """"relay":"https://relay.example/m/abc"}""",
        )

        assertThrows(TransportException.Timeout::class.java) {
            runBlocking { RelayTransport(client, resultWaitMillis = 2_500).deliver(descriptor, "{}") }
        }
        assertTrue("${polls.get()} polls in 2.5 s", polls.get() in 2..4)
    }
}
