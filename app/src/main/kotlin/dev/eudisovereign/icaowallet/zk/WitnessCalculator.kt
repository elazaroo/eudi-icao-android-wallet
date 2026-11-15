package dev.eudisovereign.icaowallet.zk

import android.annotation.SuppressLint
import android.content.Context
import android.net.Uri
import android.webkit.JavascriptInterface
import android.webkit.RenderProcessGoneDetail
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.webkit.WebViewAssetLoader
import dev.eudisovereign.icaowallet.crypto.Codec
import java.io.ByteArrayInputStream
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout

sealed class WitnessException(message: String, cause: Throwable? = null) : Exception(message, cause) {
    /** The circuit rejected the inputs: the document does not satisfy the statement. */
    class StatementFails(detail: String) : WitnessException("The circuit rejected the inputs: $detail")
    class Failed(val stage: String, detail: String) : WitnessException("Witness generation failed while $stage: $detail")
    class Transfer(detail: String) : WitnessException("Witness transfer from the WebView failed: $detail")
    class Timeout(val stage: String) : WitnessException("Witness generation timed out while $stage")
    class RendererGone(crashed: Boolean) : WitnessException(
        if (crashed) "The WebView renderer crashed" else "The WebView renderer was stopped by the system, likely for memory",
    )
}

class Witness(val bytes: ByteArray, val loadMillis: Long, val computeMillis: Long, val transferMillis: Long)

/**
 * Runs the circom witness generator (age_proof.wasm with its witness_calculator.js) in an off-screen WebView. The
 * page and its scripts are app assets served from an https origin; every other request is refused. The binary
 * witness returns in base64 chunks through a JavascriptInterface and is checked against its length and SHA-256.
 */
class WitnessCalculator(context: Context, private val timeoutMillis: Long = DEFAULT_TIMEOUT_MS) {

    private val appContext = context.applicationContext

    suspend fun calculate(inputsJson: String): Witness {
        val bridge = Bridge(inputsJson)
        var webView: WebView? = null
        try {
            return withTimeout(timeoutMillis) {
                withContext(Dispatchers.Main) {
                    webView = createWebView(bridge).also { it.loadUrl(PAGE_URL) }
                }
                bridge.result.await()
            }
        } catch (e: TimeoutCancellationException) {
            throw WitnessException.Timeout(bridge.stage)
        } finally {
            withContext(NonCancellable + Dispatchers.Main) {
                webView?.let {
                    // After onRenderProcessGone the only permitted call is destroy().
                    if (!bridge.rendererGone) {
                        it.stopLoading()
                        it.removeJavascriptInterface(BRIDGE_NAME)
                    }
                    it.destroy()
                }
            }
        }
    }

    @SuppressLint("SetJavaScriptEnabled", "JavascriptInterface")
    private fun createWebView(bridge: Bridge): WebView {
        val loader = WebViewAssetLoader.Builder()
            .setDomain(ASSET_DOMAIN)
            .addPathHandler("/assets/", WebViewAssetLoader.AssetsPathHandler(appContext))
            .build()
        return WebView(appContext).apply {
            settings.javaScriptEnabled = true
            settings.allowFileAccess = false
            settings.allowContentAccess = false
            settings.domStorageEnabled = false
            settings.mixedContentMode = WebSettings.MIXED_CONTENT_NEVER_ALLOW
            settings.javaScriptCanOpenWindowsAutomatically = false
            settings.setSupportMultipleWindows(false)
            settings.setGeolocationEnabled(false)
            settings.blockNetworkImage = true
            settings.cacheMode = WebSettings.LOAD_NO_CACHE
            settings.safeBrowsingEnabled = false
            webViewClient = object : WebViewClient() {
                override fun shouldInterceptRequest(view: WebView, request: WebResourceRequest): WebResourceResponse =
                    loader.shouldInterceptRequest(request.url)?.takeIf { isOwnAsset(request.url) } ?: refused()

                override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean = true

                override fun onRenderProcessGone(view: WebView, detail: RenderProcessGoneDetail): Boolean {
                    bridge.rendererGone = true
                    bridge.result.completeExceptionally(WitnessException.RendererGone(detail.didCrash()))
                    return true
                }
            }
            addJavascriptInterface(bridge, BRIDGE_NAME)
        }
    }

    private fun isOwnAsset(url: Uri): Boolean =
        url.scheme == "https" && url.host == ASSET_DOMAIN && url.path.orEmpty().startsWith(ASSET_PREFIX)

    private fun refused() = WebResourceResponse(
        "text/plain",
        "utf-8",
        403,
        "Forbidden",
        emptyMap(),
        ByteArrayInputStream(ByteArray(0)),
    )

    private class Bridge(private val inputsJson: String) {
        val result = CompletableDeferred<Witness>()

        @Volatile var stage: String = "loading the page"
        @Volatile var rendererGone = false
        private var buffer: ByteArray? = null
        private var expectedDigest = ""
        private var expectedChunks = 0
        private var received = 0
        private var offset = 0
        private var transferStarted = 0L

        @JavascriptInterface
        fun input(): String {
            stage = "loading age_proof.wasm"
            return inputsJson
        }

        @JavascriptInterface
        fun progress(name: String) {
            stage = name
        }

        @JavascriptInterface
        fun begin(length: Int, chunks: Int, digestHex: String) {
            if (length <= 0 || length > MAX_WITNESS_BYTES || chunks <= 0) {
                fail(WitnessException.Transfer("announced $length bytes in $chunks chunks"))
                return
            }
            stage = "transferring the witness"
            transferStarted = System.nanoTime()
            buffer = ByteArray(length)
            expectedDigest = digestHex
            expectedChunks = chunks
        }

        @JavascriptInterface
        fun chunk(index: Int, base64: String) {
            val target = buffer ?: return fail(WitnessException.Transfer("chunk $index before the transfer started"))
            if (index != received) return fail(WitnessException.Transfer("chunk $index arrived, expected $received"))
            val data = try {
                Codec.unb64(base64)
            } catch (e: IllegalArgumentException) {
                return fail(WitnessException.Transfer("chunk $index is not base64"))
            }
            if (offset + data.size > target.size) return fail(WitnessException.Transfer("chunk $index exceeds the announced length"))
            data.copyInto(target, offset)
            offset += data.size
            received++
        }

        @JavascriptInterface
        fun end(loadMillis: Double, computeMillis: Double) {
            val target = buffer ?: return fail(WitnessException.Transfer("end before the transfer started"))
            if (received != expectedChunks || offset != target.size) {
                return fail(WitnessException.Transfer("received $received of $expectedChunks chunks, $offset of ${target.size} bytes"))
            }
            if (expectedDigest.isNotEmpty() && Codec.hex(Codec.sha256(target)) != expectedDigest) {
                return fail(WitnessException.Transfer("SHA-256 of the received witness differs from the page's"))
            }
            if (target.size < 4 || String(target, 0, 4, Charsets.US_ASCII) != "wtns") {
                return fail(WitnessException.Transfer("the witness does not start with the wtns magic"))
            }
            val transferMillis = (System.nanoTime() - transferStarted) / 1_000_000
            buffer = null
            result.complete(Witness(target, loadMillis.toLong(), computeMillis.toLong(), transferMillis))
        }

        @JavascriptInterface
        fun fail(stage: String, name: String, message: String) {
            val failure = if (message.contains("Assert Failed")) {
                WitnessException.StatementFails(message.trim())
            } else {
                WitnessException.Failed(stage, "$name: ${message.trim()}")
            }
            fail(failure)
        }

        private fun fail(e: WitnessException) {
            buffer = null
            result.completeExceptionally(e)
        }
    }

    companion object {
        const val DEFAULT_TIMEOUT_MS = 240_000L
        private const val BRIDGE_NAME = "AgeWitnessBridge"
        private const val ASSET_DOMAIN = "appassets.androidplatform.net"
        private const val ASSET_PREFIX = "/assets/zk/"
        private const val PAGE_URL = "https://$ASSET_DOMAIN${ASSET_PREFIX}witness.html"
        private const val MAX_WITNESS_BYTES = 64 * 1024 * 1024
    }
}
