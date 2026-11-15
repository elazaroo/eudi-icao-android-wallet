plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.kotlin.serialization)
}

// Release signing material comes only from the user's gradle.properties or -P, never from the repository.
val releaseSigningProperties = listOf("walletKeystoreFile", "walletKeystorePassword", "walletKeyAlias", "walletKeyPassword")
    .associateWith { providers.gradleProperty(it).orNull }
val missingReleaseSigning = releaseSigningProperties.filterValues { it.isNullOrEmpty() }.keys
if (missingReleaseSigning.isNotEmpty() && missingReleaseSigning.size < releaseSigningProperties.size) {
    throw GradleException("Release signing needs all of ${releaseSigningProperties.keys}; missing $missingReleaseSigning")
}

// Non-debuggable builds block screen capture unless they are built with -PwalletAllowScreenCapture=true.
val allowScreenCapture = providers.gradleProperty("walletAllowScreenCapture").orNull == "true"

android {
    namespace = "dev.eudisovereign.icaowallet"
    compileSdk = libs.versions.compileSdk.get().toInt()

    defaultConfig {
        applicationId = "dev.eudisovereign.icaowallet"
        minSdk = libs.versions.minSdk.get().toInt()
        // targetSdk 37 gates all LAN traffic behind the ACCESS_LOCAL_NETWORK runtime permission.
        targetSdk = libs.versions.targetSdk.get().toInt()
        versionCode = 1
        versionName = "0.1.0"
        buildConfigField("boolean", "ALLOW_SCREEN_CAPTURE", allowScreenCapture.toString())
    }

    signingConfigs {
        if (missingReleaseSigning.isEmpty()) {
            create("release") {
                storeFile = file(releaseSigningProperties.getValue("walletKeystoreFile")!!)
                storePassword = releaseSigningProperties.getValue("walletKeystorePassword")
                keyAlias = releaseSigningProperties.getValue("walletKeyAlias")
                keyPassword = releaseSigningProperties.getValue("walletKeyPassword")
            }
        }
    }

    buildTypes {
        release {
            // Without the four properties the release APK stays unsigned; it never falls back to the debug key.
            signingConfig = signingConfigs.findByName("release")
            isMinifyEnabled = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    packaging {
        resources {
            // Shipped by both bcprov-jdk18on and bcutil-jdk18on.
            excludes += setOf(
                "/META-INF/LICENSE.md",
                "/META-INF/NOTICE.md",
                "/META-INF/versions/9/OSGI-INF/MANIFEST.MF",
                "/META-INF/AL2.0",
                "/META-INF/LGPL2.1",
            )
        }
    }
}

// cert-cvc (transitive of JMRTD) still declares the jdk15on BouncyCastle artifacts.
configurations.configureEach {
    exclude(group = "org.bouncycastle", module = "bcprov-jdk15on")
    exclude(group = "org.bouncycastle", module = "bcprov-jdk15to18")
}

dependencies {
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.androidx.compose.material3)
    debugImplementation(libs.androidx.compose.ui.tooling)

    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.appcompat)
    implementation(libs.androidx.fragment)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.navigation.compose)
    implementation(libs.androidx.biometric)

    implementation(libs.androidx.camera.core)
    implementation(libs.androidx.camera.camera2)
    implementation(libs.androidx.camera.lifecycle)
    implementation(libs.androidx.camera.view)
    implementation(libs.androidx.camera.mlkit.vision)
    implementation(libs.mlkit.barcode.scanning)
    implementation(libs.androidx.webkit)
    implementation(libs.rapidsnark)

    implementation(libs.kotlinx.coroutines.android)
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.okhttp)

    implementation(libs.jmrtd)
    implementation(libs.scuba.sc.android)
    implementation(libs.bouncycastle.bcprov)
    implementation(libs.bouncycastle.bcutil)

    testImplementation(libs.junit)
}
