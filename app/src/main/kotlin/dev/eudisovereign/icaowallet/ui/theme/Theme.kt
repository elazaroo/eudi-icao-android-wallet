package dev.eudisovereign.icaowallet.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.sp

private val WalletColors = darkColorScheme(
    primary = Color(0xFFC3CCD6),
    onPrimary = Color(0xFF1B1F23),
    primaryContainer = Color(0xFF2E343A),
    onPrimaryContainer = Color(0xFFDDE3E9),
    secondary = Color(0xFFA7B0BA),
    onSecondary = Color(0xFF1B1F23),
    secondaryContainer = Color(0xFF2E343A),
    onSecondaryContainer = Color(0xFFDDE3E9),
    tertiary = Color(0xFFA7B0BA),
    onTertiary = Color(0xFF1B1F23),
    background = Color(0xFF111315),
    onBackground = Color(0xFFE1E3E6),
    surface = Color(0xFF111315),
    onSurface = Color(0xFFE1E3E6),
    surfaceVariant = Color(0xFF22262A),
    onSurfaceVariant = Color(0xFFA4AAB1),
    surfaceTint = Color(0xFF111315),
    surfaceDim = Color(0xFF111315),
    surfaceBright = Color(0xFF34383D),
    surfaceContainerLowest = Color(0xFF0C0E10),
    surfaceContainerLow = Color(0xFF171A1D),
    surfaceContainer = Color(0xFF1B1E21),
    surfaceContainerHigh = Color(0xFF22262A),
    surfaceContainerHighest = Color(0xFF2B2F33),
    outline = Color(0xFF50565C),
    outlineVariant = Color(0xFF34383D),
    error = Color(0xFFE38B7A),
    onError = Color(0xFF2A1410),
    errorContainer = Color(0xFF4A2620),
    onErrorContainer = Color(0xFFF5D3CC),
)

object StatusColors {
    val pass = Color(0xFF8DBF94)
    val fail = Color(0xFFE38B7A)
    val warn = Color(0xFFD8B86F)
    val neutral = Color(0xFFA4AAB1)
}

val Mono = TextStyle(fontFamily = FontFamily.Monospace, fontSize = 13.sp, lineHeight = 18.sp)

@Composable
fun WalletTheme(content: @Composable () -> Unit) {
    MaterialTheme(colorScheme = WalletColors, typography = Typography(), content = content)
}
