// AGP 9 compiles Kotlin itself; org.jetbrains.kotlin.android must not be applied.
plugins {
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.kotlin.compose) apply false
    alias(libs.plugins.kotlin.serialization) apply false
}
