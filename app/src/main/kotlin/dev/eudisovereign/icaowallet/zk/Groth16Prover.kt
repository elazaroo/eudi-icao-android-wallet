package dev.eudisovereign.icaowallet.zk

import io.iden3.rapidsnark.RapidsnarkError
import io.iden3.rapidsnark.groth16Prove
import java.io.File

class ProverException(message: String, cause: Throwable? = null) : Exception(message, cause)

class ProverOutput(val proofJson: String, val publicSignalsJson: String)

/** Native Groth16 prover (iden3 rapidsnark); the proving key is read from its file, never loaded into the heap. */
object Groth16Prover {
    private const val PROOF_BUFFER_BYTES = 16 * 1024
    private const val PUBLIC_BUFFER_BYTES = 16 * 1024
    private const val ERROR_BUFFER_BYTES = 4 * 1024

    fun prove(provingKey: File, witness: ByteArray): ProverOutput {
        val response = try {
            groth16Prove(provingKey.absolutePath, witness, PROOF_BUFFER_BYTES, PUBLIC_BUFFER_BYTES, ERROR_BUFFER_BYTES)
        } catch (e: RapidsnarkError) {
            throw ProverException("rapidsnark ${e.javaClass.simpleName} (code ${e.code}): ${e.message}", e)
        } catch (e: LinkageError) {
            // UnsatisfiedLinkError on an ABI the library does not ship, or a failed native load
            throw ProverException("rapidsnark native library unavailable: ${e.javaClass.simpleName}: ${e.message}", e)
        }
        return ProverOutput(response.proof, response.publicSignals)
    }
}
