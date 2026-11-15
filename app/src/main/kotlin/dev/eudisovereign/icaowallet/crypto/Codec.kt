package dev.eudisovereign.icaowallet.crypto

import java.security.MessageDigest
import java.util.Base64

object Codec {

    private val HEX = "0123456789abcdef".toCharArray()

    fun hex(bytes: ByteArray): String {
        val out = CharArray(bytes.size * 2)
        for (i in bytes.indices) {
            val v = bytes[i].toInt() and 0xFF
            out[2 * i] = HEX[v ushr 4]
            out[2 * i + 1] = HEX[v and 0x0F]
        }
        return String(out)
    }

    fun unhex(text: String): ByteArray {
        require(text.length % 2 == 0) { "Hex string has odd length" }
        return ByteArray(text.length / 2) { i ->
            val hi = Character.digit(text[2 * i], 16)
            val lo = Character.digit(text[2 * i + 1], 16)
            require(hi >= 0 && lo >= 0) { "Invalid hex character" }
            ((hi shl 4) or lo).toByte()
        }
    }

    fun b64(bytes: ByteArray): String = Base64.getEncoder().encodeToString(bytes)

    fun unb64(text: String): ByteArray = Base64.getDecoder().decode(text)

    fun b64url(bytes: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

    fun unb64url(text: String): ByteArray {
        require('=' !in text) { "base64url value must not be padded" }
        return Base64.getUrlDecoder().decode(text)
    }

    fun sha256(bytes: ByteArray): ByteArray = digest("SHA-256", bytes)

    fun sha1(bytes: ByteArray): ByteArray = digest("SHA-1", bytes)

    fun digest(algorithm: String, bytes: ByteArray): ByteArray =
        MessageDigest.getInstance(algorithm).digest(bytes)
}
