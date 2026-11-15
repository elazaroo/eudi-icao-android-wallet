package dev.eudisovereign.icaowallet.zk

import dev.eudisovereign.icaowallet.crypto.Codec
import java.io.File
import java.security.MessageDigest
import java.util.Collections
import java.util.concurrent.atomic.AtomicInteger
import kotlin.random.Random
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import okhttp3.Interceptor
import okhttp3.MediaType
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.Response
import okhttp3.ResponseBody
import okhttp3.ResponseBody.Companion.toResponseBody
import okio.Buffer
import okio.BufferedSource
import okio.Source
import okio.Timeout
import okio.buffer
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class ProvingKeyDownloaderTest {

    @get:Rule
    val folder = TemporaryFolder()

    private val content = Random(7).nextBytes(300_000)
    private val source = ProvingKeySource(PUBLISHED_URL, content.size.toLong(), sha256(content))

    private fun directory(): File = File(folder.root, "zk")

    private fun target(): File = File(directory(), "age_proof.zkey")

    private fun leftovers(): List<String> = directory().list()?.toList().orEmpty()

    private fun client(interceptor: Interceptor) = OkHttpClient.Builder().addInterceptor(interceptor).build()

    private fun downloader(interceptor: Interceptor, freeSpace: (File) -> Long = { Long.MAX_VALUE }) =
        ProvingKeyDownloader(client(interceptor), source, freeSpace, progressStep = 16 * 1024L)

    @Test
    fun followsTheRedirectAndMovesTheVerifiedFileIntoPlace() {
        val hosts = Collections.synchronizedList(mutableListOf<String>())
        val progress = mutableListOf<Long>()
        val interceptor = Interceptor { chain ->
            val request = chain.request()
            hosts += request.url.host
            if (request.url.host == "github.com") {
                response(request, 302).header("Location", REDIRECTED_URL).body(ByteArray(0).toResponseBody()).build()
            } else {
                response(request, 200).body(content.toResponseBody()).build()
            }
        }

        runBlocking { downloader(interceptor).download(target()) { progress += it } }

        assertEquals(listOf("github.com", "objects.example"), hosts)
        assertArrayEquals(content, target().readBytes())
        assertEquals(listOf("age_proof.zkey"), leftovers())
        assertEquals(content.size.toLong(), progress.last())
    }

    @Test
    fun hashMismatchLeavesNoFile() {
        val altered = content.copyOf().also { it[it.size / 2] = (it[it.size / 2] + 1).toByte() }
        val interceptor = Interceptor { chain -> response(chain.request(), 200).body(altered.toResponseBody()).build() }

        assertThrows(KeyDownloadException.Mismatch::class.java) {
            runBlocking { downloader(interceptor).download(target()) {} }
        }
        assertEquals(emptyList<String>(), leftovers())
    }

    @Test
    fun truncatedBodyLeavesNoFile() {
        val partial = content.copyOf(content.size / 3)
        val interceptor = Interceptor { chain ->
            response(chain.request(), 200).body(body(Buffer().write(partial), content.size.toLong())).build()
        }

        assertThrows(KeyDownloadException.Interrupted::class.java) {
            runBlocking { downloader(interceptor).download(target()) {} }
        }
        assertEquals(emptyList<String>(), leftovers())
    }

    @Test
    fun httpErrorReportsItsStatus() {
        val interceptor = Interceptor { chain -> response(chain.request(), 404).body("Not Found".toResponseBody()).build() }

        val error = assertThrows(KeyDownloadException.Http::class.java) {
            runBlocking { downloader(interceptor).download(target()) {} }
        }
        assertEquals(404, error.status)
        assertEquals(emptyList<String>(), leftovers())
    }

    @Test
    fun redirectToCleartextIsRefused() {
        val interceptor = Interceptor { chain ->
            response(chain.request(), 302).header("Location", "http://objects.example/age_proof.zkey")
                .body(ByteArray(0).toResponseBody()).build()
        }

        assertThrows(KeyDownloadException.Protocol::class.java) {
            runBlocking { downloader(interceptor).download(target()) {} }
        }
        assertEquals(emptyList<String>(), leftovers())
    }

    @Test
    fun cancellationRemovesThePartialFile() {
        val interceptor = Interceptor { chain ->
            response(chain.request(), 200).body(body(SlowSource().buffer(), content.size.toLong())).build()
        }
        runBlocking {
            val receiving = CompletableDeferred<Unit>()
            val job = launch(Dispatchers.IO) { downloader(interceptor).download(target()) { receiving.complete(Unit) } }
            receiving.await()
            assertEquals(1, leftovers().count { it.endsWith(ProvingKeyDownloader.TEMP_SUFFIX) })
            job.cancelAndJoin()
            assertTrue(job.isCancelled)
        }
        assertEquals(emptyList<String>(), leftovers())
    }

    @Test
    fun insufficientSpaceIsReportedBeforeAnyRequest() {
        val requests = AtomicInteger()
        val interceptor = Interceptor { chain ->
            requests.incrementAndGet()
            response(chain.request(), 200).body(content.toResponseBody()).build()
        }
        val available = source.size + ProvingKeyDownloader.SPACE_MARGIN - 1

        val error = assertThrows(KeyDownloadException.InsufficientSpace::class.java) {
            runBlocking { downloader(interceptor, freeSpace = { available }).download(target()) {} }
        }
        assertEquals(available, error.available)
        assertEquals(source.size + ProvingKeyDownloader.SPACE_MARGIN, error.required)
        assertEquals(0, requests.get())
        assertEquals(emptyList<String>(), leftovers())
    }

    private class SlowSource : Source {
        override fun read(sink: Buffer, byteCount: Long): Long {
            Thread.sleep(10)
            val count = minOf(byteCount, 1024L)
            sink.write(ByteArray(count.toInt()))
            return count
        }

        override fun timeout(): Timeout = Timeout.NONE

        override fun close() = Unit
    }

    private companion object {
        const val PUBLISHED_URL = "https://github.com/owner/repo/releases/download/v1/age_proof.zkey"
        const val REDIRECTED_URL = "https://objects.example/release-asset/age_proof.zkey?signature=abc"

        fun response(request: Request, code: Int): Response.Builder =
            Response.Builder().request(request).protocol(Protocol.HTTP_1_1).code(code).message("")

        fun body(source: BufferedSource, length: Long): ResponseBody = object : ResponseBody() {
            override fun contentType(): MediaType? = null

            override fun contentLength(): Long = length

            override fun source(): BufferedSource = source
        }

        fun sha256(bytes: ByteArray): String = Codec.hex(MessageDigest.getInstance("SHA-256").digest(bytes))
    }
}
