package dev.eudisovereign.icaowallet.nfc

import java.time.DateTimeException
import java.time.LocalDate
import java.util.Locale
import org.jmrtd.BACKey
import org.jmrtd.PACEKeySpec

enum class AccessKeyKind(val label: String) {
    CAN("CAN"),
    MRZ("MRZ data"),
}

sealed class AccessKey {
    abstract val kind: AccessKeyKind

    abstract fun paceKey(): PACEKeySpec

    class Can(val number: String) : AccessKey() {
        init {
            AccessKeyRules.canProblem(number)?.let { throw IllegalArgumentException(it) }
        }

        override val kind: AccessKeyKind get() = AccessKeyKind.CAN

        override fun paceKey(): PACEKeySpec = PACEKeySpec.createCANKey(number)

        override fun toString(): String = "AccessKey.Can"
    }

    class Mrz(val documentNumber: String, val dateOfBirth: String, val dateOfExpiry: String) : AccessKey() {
        init {
            val problems = AccessKeyRules.mrzProblems(documentNumber, dateOfBirth, dateOfExpiry)
            require(problems.isEmpty()) { problems.joinToString("; ") }
        }

        override val kind: AccessKeyKind get() = AccessKeyKind.MRZ

        // ICAO 9303-11: BAC and PACE derive their keys from the same MRZ information; JMRTD adds the check digits
        fun bacKey(): BACKey = BACKey(documentNumber, dateOfBirth, dateOfExpiry)

        override fun paceKey(): PACEKeySpec = PACEKeySpec.createMRZKey(bacKey())

        override fun toString(): String = "AccessKey.Mrz"
    }
}

object AccessKeyRules {
    const val CAN_LENGTH = 6
    const val DOCUMENT_NUMBER_MAX_LENGTH = 9
    const val DATE_LENGTH = 6

    private val documentNumberPattern = Regex("[A-Z0-9][A-Z0-9<]{0,${DOCUMENT_NUMBER_MAX_LENGTH - 1}}")

    fun filterCan(raw: String): String = raw.filter { it in '0'..'9' }.take(CAN_LENGTH)

    fun filterDocumentNumber(raw: String): String = raw.uppercase(Locale.ROOT)
        .filter { it in 'A'..'Z' || it in '0'..'9' || it == '<' }
        .take(DOCUMENT_NUMBER_MAX_LENGTH)

    fun filterDate(raw: String): String = raw.filter { it in '0'..'9' }.take(DATE_LENGTH)

    fun canProblem(can: String): String? =
        if (can.length == CAN_LENGTH && can.all { it in '0'..'9' }) null else "The CAN must be exactly $CAN_LENGTH digits"

    fun documentNumberProblem(documentNumber: String): String? = when {
        documentNumber.isEmpty() -> "The document number is empty"
        documentNumber.length > DOCUMENT_NUMBER_MAX_LENGTH ->
            "The document number has more than $DOCUMENT_NUMBER_MAX_LENGTH characters"
        !documentNumberPattern.matches(documentNumber) ->
            "The document number must start with A-Z or 0-9 and contain only A-Z, 0-9 and <"
        else -> null
    }

    fun dateProblem(label: String, date: String): String? = when {
        date.length != DATE_LENGTH || !date.all { it in '0'..'9' } -> "$label must be exactly $DATE_LENGTH digits (YYMMDD)"
        !isCalendarDate(date) -> "$label is not a valid calendar date (YYMMDD)"
        else -> null
    }

    fun mrzProblems(documentNumber: String, dateOfBirth: String, dateOfExpiry: String): List<String> = listOfNotNull(
        documentNumberProblem(documentNumber),
        dateProblem("The date of birth", dateOfBirth),
        dateProblem("The date of expiry", dateOfExpiry),
    )

    // The MRZ has no century; every YY divisible by 4 is a leap year in 20YY, so 2000 + YY accepts 29 February
    // whenever some century makes it valid.
    private fun isCalendarDate(yymmdd: String): Boolean = try {
        LocalDate.of(
            2000 + yymmdd.substring(0, 2).toInt(),
            yymmdd.substring(2, 4).toInt(),
            yymmdd.substring(4, 6).toInt(),
        )
        true
    } catch (e: DateTimeException) {
        false
    }
}
