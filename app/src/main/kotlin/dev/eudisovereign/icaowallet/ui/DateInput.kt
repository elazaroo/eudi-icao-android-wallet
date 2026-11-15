package dev.eudisovereign.icaowallet.ui

import java.time.DateTimeException
import java.time.LocalDate

enum class DateProblem { INCOMPLETE, NOT_A_DATE, OUT_OF_RANGE, IN_FUTURE }

sealed interface DateParse {
    class Valid(val date: LocalDate) : DateParse {
        /** The YYMMDD form the MRZ and the access key use. */
        val yymmdd: String get() = "%02d%02d%02d".format(date.year % 100, date.monthValue, date.dayOfMonth)
    }

    class Invalid(val problem: DateProblem) : DateParse
}

/** Dates are typed as the eight digits of DD/MM/YYYY; the slashes are only displayed. */
object DateInput {
    const val DIGITS = 8
    const val MIN_YEAR = 1900
    const val MAX_YEAR = 2099

    fun filter(raw: String): String = raw.filter { it in '0'..'9' }.take(DIGITS)

    fun parse(digits: String, notAfter: LocalDate? = null): DateParse {
        if (digits.length != DIGITS || !digits.all { it in '0'..'9' }) return DateParse.Invalid(DateProblem.INCOMPLETE)
        val day = digits.substring(0, 2).toInt()
        val month = digits.substring(2, 4).toInt()
        val year = digits.substring(4, 8).toInt()
        if (year !in MIN_YEAR..MAX_YEAR) return DateParse.Invalid(DateProblem.OUT_OF_RANGE)
        val date = try {
            LocalDate.of(year, month, day)
        } catch (e: DateTimeException) {
            return DateParse.Invalid(DateProblem.NOT_A_DATE)
        }
        if (notAfter != null && date.isAfter(notAfter)) return DateParse.Invalid(DateProblem.IN_FUTURE)
        return DateParse.Valid(date)
    }

    /** Null unless [digits] is a complete, valid date. */
    fun toYymmdd(digits: String, notAfter: LocalDate? = null): String? =
        (parse(digits, notAfter) as? DateParse.Valid)?.yymmdd

    fun display(digits: String): String = buildString {
        digits.forEachIndexed { index, c ->
            append(c)
            if ((index == 1 || index == 3) && index < digits.lastIndex) append('/')
        }
    }

    fun displayOffset(originalOffset: Int, length: Int): Int {
        val shifted = when {
            originalOffset <= 2 -> originalOffset
            originalOffset <= 4 -> originalOffset + 1
            else -> originalOffset + 2
        }
        return shifted.coerceIn(0, display("0".repeat(length)).length)
    }

    fun originalOffset(displayOffset: Int, length: Int): Int {
        val shifted = when {
            displayOffset <= 2 -> displayOffset
            displayOffset <= 5 -> displayOffset - 1
            else -> displayOffset - 2
        }
        return shifted.coerceIn(0, length)
    }
}
