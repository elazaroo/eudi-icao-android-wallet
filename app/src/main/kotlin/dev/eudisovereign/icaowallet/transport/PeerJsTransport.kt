package dev.eudisovereign.icaowallet.transport

import android.annotation.SuppressLint
import android.content.Context
import android.webkit.JavascriptInterface
import android.webkit.WebResourceRequest
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import dev.eudisovereign.icaowallet.protocol.FrameException
import dev.eudisovereign.icaowallet.protocol.PartFrame
import dev.eudisovereign.icaowallet.protocol.ResultFrame
import dev.eudisovereign.icaowallet.protocol.SessionDescriptor
import java.util.concurrent.atomic.AtomicReference
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive

internal object PeerJsPage {

    private val forbidden = listOf("</script", "<script", "<!--")
    private val placeholders = Regex("__TARGET__|__PARTS__")

    /**
     * The library is inlined verbatim, so it must not contain a sequence that ends or escapes the HTML script data
     * state. Data is embedded as JSON literals with markup characters escaped.
     */
    fun build(library: String, peerId: String, parts: List<String>): String {
        val lower = library.lowercase()
        forbidden.firstOrNull { it in lower }?.let {
            throw IllegalStateException("peerjs build contains \"$it\" and cannot be inlined")
        }
        val target = scriptSafe(JsonPrimitive(peerId).toString())
        val frames = scriptSafe(JsonArray(parts.map(::JsonPrimitive)).toString())
        return buildString {
            append("<!doctype html><html><head><meta charset=\"utf-8\"></head><body>\n<script>\n")
            append(library)
            append("\n</script>\n<script>\n")
            // One pass, so a placeholder inside the embedded data is never substituted again.
            append(placeholders.replace(BRIDGE_SCRIPT) { if (it.value == "__TARGET__") target else frames })
            append("\n</script>\n</body></html>")
        }
    }

    internal fun scriptSafe(jsonLiteral: String): String = buildString(jsonLiteral.length) {
        for (c in jsonLiteral) {
            when (c) {
                '<' -> append("\\u003c")
                '>' -> append("\\u003e")
                '&' -> append("\\u0026")
                '\u2028' -> append("\\u2028")
                '\u2029' -> append("\\u2029")
                else -> append(c)
            }
        }
    }

    private val BRIDGE_SCRIPT = """
        (function () {
          var bridge = window.$BRIDGE_NAME;
          var target = __TARGET__;
          var parts = __PARTS__;
          var finished = false;
          function fail(type, message) {
            if (finished) return;
            finished = true;
            bridge.error(String(type), String(message));
          }
          function asText(data) {
            if (typeof data === "string") return data;
            if (data instanceof ArrayBuffer || ArrayBuffer.isView(data)) return new TextDecoder("utf-8").decode(data);
            return null;
          }
          var peer = new Peer({ debug: 0 });
          peer.on("error", function (e) { fail(e && e.type ? e.type : "peer", e && e.message ? e.message : e); });
          peer.on("open", function () {
            var conn = peer.connect(target, { serialization: "raw", reliable: true });
            conn.on("open", function () {
              bridge.open();
              for (var i = 0; i < parts.length; i++) conn.send(parts[i]);
              bridge.sent();
            });
            conn.on("data", function (data) {
              var text = asText(data);
              if (text === null) { fail("protocol", "unsupported frame type"); return; }
              bridge.data(text);
            });
            conn.on("error", function (e) { fail(e && e.type ? e.type : "connection", e && e.message ? e.message : e); });
            conn.on("close", function () { fail("closed", "data connection closed by the verifier"); });
          });
        })();
    """.trimIndent()

    const val BRIDGE_NAME = "WalletBridge"
}

/**
 * Runs the official peerjs browser build in an off-screen WebView so that the wire protocol is the one the
 * browser verifier speaks. The WebView only receives the sealed envelope.
 */
class PeerJsTransport(
    context: Context,
    private val timeoutMillis: Long = DEFAULT_TIMEOUT_MS,
) : Transport {

    private val appContext = context.applicationContext

    override suspend fun deliver(descriptor: SessionDescriptor, envelopeJson: String): ResultFrame {
        val page = withContext(Dispatchers.IO) {
            val library = appContext.assets.open(LIBRARY_ASSET).use { it.readBytes().toString(Charsets.UTF_8) }
            PeerJsPage.build(library, descriptor.peerId, PartFrame.split(envelopeJson))
        }
        val bridge = Bridge()
        var webView: WebView? = null
        try {
            return withTimeout(timeoutMillis) {
                withContext(Dispatchers.Main) {
                    webView = createWebView(bridge).also {
                        it.loadDataWithBaseURL(BASE_URL, page, "text/html", "utf-8", null)
                    }
                }
                bridge.result.await()
            }
        } catch (e: TimeoutCancellationException) {
            throw TransportException.Timeout(bridge.stage.get())
        } finally {
            withContext(NonCancellable + Dispatchers.Main) {
                webView?.let {
                    it.stopLoading()
                    it.removeJavascriptInterface(PeerJsPage.BRIDGE_NAME)
                    it.destroy()
                }
            }
        }
    }

    @SuppressLint("SetJavaScriptEnabled", "JavascriptInterface")
    private fun createWebView(bridge: Bridge): WebView = WebView(appContext).apply {
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
        webViewClient = object : WebViewClient() {
            override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean = true
        }
        addJavascriptInterface(bridge, PeerJsPage.BRIDGE_NAME)
    }

    private class Bridge {
        val result = CompletableDeferred<ResultFrame>()
        val stage = AtomicReference("connecting to the verifier peer")

        @JavascriptInterface
        fun open() {
            stage.set("sending the envelope")
        }

        @JavascriptInterface
        fun sent() {
            stage.set("waiting for the verification result")
        }

        @JavascriptInterface
        fun data(text: String) {
            try {
                ResultFrame.decode(text)?.let { result.complete(it) }
            } catch (e: FrameException) {
                result.completeExceptionally(TransportException.Protocol(e.message ?: "Malformed frame", e))
            }
        }

        @JavascriptInterface
        fun error(type: String, message: String) {
            val failure = when (type) {
                "peer-unavailable" -> TransportException.PeerUnavailable(message)
                else -> TransportException.Connection("$type: $message")
            }
            result.completeExceptionally(failure)
        }
    }

    companion object {
        const val DEFAULT_TIMEOUT_MS = 90_000L
        private const val LIBRARY_ASSET = "peerjs/peerjs.min.js"
        private const val BASE_URL = "https://wallet.invalid/"
    }
}
