package dev.eudisovereign.icaowallet.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import androidx.annotation.StringRes
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import dev.eudisovereign.icaowallet.R
import dev.eudisovereign.icaowallet.protocol.Binding
import dev.eudisovereign.icaowallet.report.ChainExpiry
import dev.eudisovereign.icaowallet.ui.theme.Mono
import dev.eudisovereign.icaowallet.ui.theme.StatusColors
import java.time.Instant
import java.time.ZoneId
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.time.format.FormatStyle
import java.util.Locale

@Composable
fun ScreenScaffold(
    title: String,
    onBack: (() -> Unit)?,
    content: @Composable ColumnScope.() -> Unit,
) {
    Scaffold(
        topBar = {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .statusBarsPadding()
                    .padding(horizontal = 8.dp, vertical = 4.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                if (onBack != null) {
                    TextButton(onClick = onBack) { Text(stringResource(R.string.action_back)) }
                } else {
                    Spacer(Modifier.width(8.dp))
                }
                Text(
                    text = title,
                    style = MaterialTheme.typography.titleLarge,
                    modifier = Modifier.padding(start = 8.dp),
                )
            }
        },
    ) { padding: PaddingValues ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .imePadding()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp, vertical = 8.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
            content = content,
        )
    }
}

@Composable
fun Section(title: String, content: @Composable ColumnScope.() -> Unit) {
    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
        HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
        Text(
            text = title.uppercase(currentLocale()),
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            fontWeight = FontWeight.SemiBold,
            modifier = Modifier.padding(top = 4.dp),
        )
        content()
    }
}

@Composable
fun Field(label: String, value: String, mono: Boolean = false, valueColor: Color = Color.Unspecified) {
    Column(Modifier.fillMaxWidth()) {
        Text(label, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        SelectionContainer {
            Text(
                text = value,
                style = if (mono) Mono else MaterialTheme.typography.bodyMedium,
                color = valueColor,
            )
        }
    }
}

@Composable
fun MonoBlock(text: String, color: Color = Color.Unspecified) {
    SelectionContainer {
        Text(text = text, style = Mono, color = color, modifier = Modifier.fillMaxWidth())
    }
}

@Composable
fun Note(text: String, color: Color = MaterialTheme.colorScheme.onSurfaceVariant) {
    Text(text = text, style = MaterialTheme.typography.bodySmall, color = color)
}

@Composable
fun Body(text: String, color: Color = Color.Unspecified) {
    Text(text = text, style = MaterialTheme.typography.bodyLarge, color = color)
}

@Composable
fun ErrorPanel(title: String, detail: String) {
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text(title, style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.error)
        MonoBlock(detail, color = MaterialTheme.colorScheme.error)
    }
}

/** A failure in plain words; the technical detail stays behind a Details control. */
@Composable
fun ProblemCard(
    failure: Failure,
    details: @Composable ColumnScope.() -> Unit = {},
    actions: @Composable ColumnScope.() -> Unit = {},
) {
    var expanded by remember(failure) { mutableStateOf(false) }
    Card(
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.errorContainer,
            contentColor = MaterialTheme.colorScheme.onErrorContainer,
        ),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(failureText(failure.problem.titleRes(), failure.number), style = MaterialTheme.typography.titleMedium)
            failure.problem.hintRes()?.let {
                Text(failureText(it, failure.number), style = MaterialTheme.typography.bodyMedium)
            }
            actions()
            DetailsToggle(expanded) { expanded = !expanded }
            if (expanded) {
                MonoBlock(failure.detail)
                details()
            }
        }
    }
}

@Composable
private fun failureText(@StringRes id: Int, number: Long?): String =
    if (number == null) stringResource(id) else stringResource(id, number)

@Composable
fun MessageCard(title: String, text: String?, warning: Boolean, content: @Composable ColumnScope.() -> Unit = {}) {
    Card(
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceContainerHigh,
            contentColor = MaterialTheme.colorScheme.onSurface,
        ),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(
                text = title,
                style = MaterialTheme.typography.titleMedium,
                color = if (warning) StatusColors.warn else Color.Unspecified,
            )
            if (text != null) Text(text, style = MaterialTheme.typography.bodyMedium)
            content()
        }
    }
}

@Composable
fun DetailsToggle(expanded: Boolean, onToggle: () -> Unit) {
    TextButton(onClick = onToggle) {
        Text(stringResource(if (expanded) R.string.action_hide_details else R.string.action_details))
    }
}

@Composable
fun PrimaryAction(text: String, enabled: Boolean = true, onClick: () -> Unit) {
    Button(onClick = onClick, enabled = enabled, modifier = Modifier.fillMaxWidth()) { Text(text) }
}

@Composable
fun SecondaryAction(text: String, enabled: Boolean = true, onClick: () -> Unit) {
    OutlinedButton(onClick = onClick, enabled = enabled, modifier = Modifier.fillMaxWidth()) { Text(text) }
}

@Composable
fun StepRow(label: String, status: String, statusColor: Color, durationMillis: Long?, detail: String?) {
    Column(Modifier.fillMaxWidth()) {
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.Top) {
            Text(
                text = status,
                style = Mono,
                color = statusColor,
                modifier = Modifier.width(72.dp),
            )
            Text(text = label, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f))
            if (durationMillis != null) {
                Text(text = "$durationMillis ms", style = Mono, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
        if (!detail.isNullOrEmpty()) {
            Text(
                text = detail,
                style = Mono,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(start = 72.dp),
            )
        }
        Spacer(Modifier.height(2.dp))
    }
}

enum class Mark { PASS, FAIL, PENDING, ACTIVE }

/** A drawn status mark; the description is announced by accessibility services. */
@Composable
fun StatusMark(mark: Mark, description: String, size: Dp = 24.dp) {
    val color = when (mark) {
        Mark.PASS -> StatusColors.pass
        Mark.FAIL -> StatusColors.fail
        Mark.ACTIVE -> StatusColors.warn
        Mark.PENDING -> StatusColors.neutral
    }
    Canvas(Modifier.size(size).semantics { contentDescription = description }) {
        val stroke = this.size.minDimension / 10f
        val radius = this.size.minDimension / 2f - stroke / 2f
        drawCircle(color = color, radius = radius, style = Stroke(width = stroke))
        val w = this.size.width
        val h = this.size.height
        when (mark) {
            Mark.PASS -> {
                drawLine(color, Offset(w * 0.30f, h * 0.52f), Offset(w * 0.45f, h * 0.67f), stroke, StrokeCap.Round)
                drawLine(color, Offset(w * 0.45f, h * 0.67f), Offset(w * 0.72f, h * 0.37f), stroke, StrokeCap.Round)
            }
            Mark.FAIL -> {
                drawLine(color, Offset(w * 0.34f, h * 0.34f), Offset(w * 0.66f, h * 0.66f), stroke, StrokeCap.Round)
                drawLine(color, Offset(w * 0.66f, h * 0.34f), Offset(w * 0.34f, h * 0.66f), stroke, StrokeCap.Round)
            }
            Mark.ACTIVE -> drawCircle(color = color, radius = radius / 2.5f)
            Mark.PENDING -> Unit
        }
    }
}

@Composable
fun MarkedRow(mark: Mark, markDescription: String, text: String, emphasised: Boolean = false) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        StatusMark(mark, markDescription)
        Text(
            text = text,
            style = if (emphasised) MaterialTheme.typography.titleMedium else MaterialTheme.typography.bodyLarge,
            modifier = Modifier.weight(1f),
        )
    }
}

@Composable
fun BuildIdentityContent(state: IdentityState, showPolicyEntry: Boolean) {
    when (state) {
        IdentityState.Loading -> Note(stringResource(R.string.identity_loading))
        is IdentityState.Failed -> ErrorPanel(stringResource(R.string.identity_failed), state.detail)
        is IdentityState.Ready -> {
            val identity = state.identity
            val context = LocalContext.current
            var copied by remember { mutableStateOf(false) }
            val fragment = identity.policyFragment()
            Field(stringResource(R.string.identity_package), identity.packageName, mono = true)
            Field(stringResource(R.string.identity_certificate), identity.signingCertSha256.joinToString("\n"), mono = true)
            if (showPolicyEntry) Field(stringResource(R.string.identity_policy_entry), fragment, mono = true)
            SecondaryAction(stringResource(R.string.identity_copy)) {
                copyToClipboard(context, "allowedApps", fragment)
                copied = true
            }
            if (copied) Note(stringResource(R.string.identity_copied))
            if (identity.debuggable) Note(stringResource(R.string.identity_debuggable), color = StatusColors.fail)
        }
    }
}

@Composable
fun AttestationExpiryField(expiry: ChainExpiry, binding: Binding, showSubject: Boolean) {
    val expired = expiry.isExpired(System.currentTimeMillis())
    val certificate = "certificate [${expiry.index}]" + if (showSubject) " ${expiry.subject}" else ""
    val suffix = if (expired) "  [" + stringResource(R.string.tech_expired) + "]" else ""
    Field(
        label = stringResource(R.string.tech_attestation_valid_until),
        value = formatUtc(expiry.notAfterMillis) + suffix + "\n$certificate",
        mono = true,
        valueColor = when {
            !expired -> Color.Unspecified
            binding == Binding.CA_ATTESTATION -> StatusColors.fail
            else -> StatusColors.warn
        },
    )
}

private fun copyToClipboard(context: Context, label: String, text: String) {
    val clipboard = context.getSystemService(ClipboardManager::class.java) ?: return
    clipboard.setPrimaryClip(ClipData.newPlainText(label, text))
}

fun checkColor(valid: Boolean?): Color = when (valid) {
    true -> StatusColors.pass
    false -> StatusColors.fail
    null -> Color.Unspecified
}

@Composable
fun currentLocale(): Locale {
    val locales = LocalConfiguration.current.locales
    return if (locales.isEmpty) Locale.getDefault() else locales[0]
}

private val utcFormat = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss 'UTC'").withZone(ZoneOffset.UTC)
private val localFormat = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss xxx")

fun formatUtc(millis: Long): String = utcFormat.format(Instant.ofEpochMilli(millis))

fun formatLocal(millis: Long): String = localFormat.withZone(ZoneId.systemDefault()).format(Instant.ofEpochMilli(millis))

fun formatDate(millis: Long, locale: Locale): String =
    DateTimeFormatter.ofLocalizedDate(FormatStyle.LONG)
        .withLocale(locale)
        .withZone(ZoneId.systemDefault())
        .format(Instant.ofEpochMilli(millis))
