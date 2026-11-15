package dev.eudisovereign.icaowallet.transport

import dev.eudisovereign.icaowallet.protocol.ResultFrame
import dev.eudisovereign.icaowallet.protocol.SessionDescriptor

sealed class TransportException(message: String, cause: Throwable? = null) : Exception(message, cause) {
    class Timeout(val stage: String) : TransportException("Timed out $stage")
    class PeerUnavailable(detail: String) : TransportException("Verifier peer is not reachable: $detail")
    class Connection(detail: String, cause: Throwable? = null) : TransportException("Connection failed: $detail", cause)
    class Http(val status: Int, val stage: String) : TransportException("Relay answered HTTP $status while $stage")
    class TooLarge(val size: Int, val limit: Int) :
        TransportException("Envelope is $size bytes, the relay accepts at most $limit")
    class Protocol(detail: String, cause: Throwable? = null) : TransportException(detail, cause)
}

/** Delivers a sealed envelope (spec section 3) and returns the verifier's result frame (spec 6.1). */
interface Transport {
    suspend fun deliver(descriptor: SessionDescriptor, envelopeJson: String): ResultFrame
}
