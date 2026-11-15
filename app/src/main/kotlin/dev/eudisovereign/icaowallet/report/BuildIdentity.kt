package dev.eudisovereign.icaowallet.report

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.content.pm.Signature
import android.os.Build
import dev.eudisovereign.icaowallet.crypto.Codec
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray

class BuildIdentity(val packageName: String, val signingCertSha256: List<String>, val debuggable: Boolean) {

    /** One entry of allowedApps in the verifier's attestation policy (spec section 5). */
    fun policyFragment(): String = buildJsonObject {
        put("packageName", packageName)
        putJsonArray("signingCertSha256") { signingCertSha256.forEach { add(it) } }
    }.toString()

    companion object {
        fun of(context: Context): BuildIdentity {
            val packageName = context.packageName
            val signers = signers(context.packageManager, packageName)
            check(signers.isNotEmpty()) { "PackageManager reports no signing certificate for $packageName" }
            return BuildIdentity(
                packageName = packageName,
                signingCertSha256 = signers.map { Codec.hex(Codec.sha256(it.toByteArray())) },
                debuggable = (context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0,
            )
        }

        // Keystore attestation lists the signing certificate history, or every signer for multi-signer APKs.
        private fun signers(pm: PackageManager, packageName: String): List<Signature> {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) {
                @Suppress("DEPRECATION")
                val info = pm.getPackageInfo(packageName, PackageManager.GET_SIGNATURES)
                @Suppress("DEPRECATION")
                return info.signatures?.toList().orEmpty()
            }
            val info = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.getPackageInfo(
                    packageName,
                    PackageManager.PackageInfoFlags.of(PackageManager.GET_SIGNING_CERTIFICATES.toLong()),
                )
            } else {
                @Suppress("DEPRECATION")
                pm.getPackageInfo(packageName, PackageManager.GET_SIGNING_CERTIFICATES)
            }
            val signingInfo = info.signingInfo ?: return emptyList()
            val signatures = if (signingInfo.hasMultipleSigners()) {
                signingInfo.apkContentsSigners
            } else {
                signingInfo.signingCertificateHistory
            }
            return signatures?.toList().orEmpty()
        }
    }
}
