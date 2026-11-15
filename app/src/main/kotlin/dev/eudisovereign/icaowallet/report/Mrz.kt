package dev.eudisovereign.icaowallet.report

enum class MrzFormat(val lineLength: Int, val lineCount: Int) {
    TD1(30, 3),
    TD2(36, 2),
    TD3(44, 2),
}

enum class MrzFieldId {
    DOCUMENT_CODE,
    ISSUING_STATE,
    DOCUMENT_NUMBER,
    PERSONAL_NUMBER,
    OPTIONAL_DATA_1,
    OPTIONAL_DATA_2,
    DATE_OF_BIRTH,
    SEX,
    DATE_OF_EXPIRY,
    NATIONALITY,
    PRIMARY_IDENTIFIER,
    SECONDARY_IDENTIFIER,
    COMPOSITE_CHECK,
}

class MrzField(val id: MrzFieldId, val label: String, val value: String, val checkValid: Boolean? = null)

class Mrz private constructor(
    val format: MrzFormat,
    val lines: List<String>,
    val documentCode: String,
    val issuingState: String,
    val documentNumber: String,
    val documentNumberValid: Boolean,
    val dateOfBirth: String,
    val dateOfBirthValid: Boolean,
    val sex: String,
    val dateOfExpiry: String,
    val dateOfExpiryValid: Boolean,
    val nationality: String,
    val primaryIdentifier: String,
    val secondaryIdentifier: String,
    val optionalData1: String,
    val optionalData2: String?,
    val optionalData1Valid: Boolean?,
    val compositeValid: Boolean,
) {
    val documentType: String
        get() {
            val kind = when (documentCode.firstOrNull()) {
                'P' -> "Passport"
                'I', 'A', 'C' -> "Identity card"
                'V' -> "Visa"
                else -> "Travel document"
            }
            return "$kind (${format.name})"
        }

    val checksValid: Boolean
        get() = documentNumberValid && dateOfBirthValid && dateOfExpiryValid && compositeValid &&
            optionalData1Valid != false

    fun fields(): List<MrzField> = listOfNotNull(
        MrzField(MrzFieldId.DOCUMENT_CODE, "Document code", documentCode),
        MrzField(MrzFieldId.ISSUING_STATE, "Issuing state", issuingState),
        MrzField(MrzFieldId.DOCUMENT_NUMBER, "Document number", documentNumber, documentNumberValid),
        if (format == MrzFormat.TD3) {
            MrzField(MrzFieldId.PERSONAL_NUMBER, "Personal number", optionalData1, optionalData1Valid)
        } else {
            MrzField(MrzFieldId.OPTIONAL_DATA_1, "Optional data 1", optionalData1, optionalData1Valid)
        },
        optionalData2?.let { MrzField(MrzFieldId.OPTIONAL_DATA_2, "Optional data 2", it) },
        MrzField(MrzFieldId.DATE_OF_BIRTH, "Date of birth (YYMMDD)", dateOfBirth, dateOfBirthValid),
        MrzField(MrzFieldId.SEX, "Sex", sex),
        MrzField(MrzFieldId.DATE_OF_EXPIRY, "Date of expiry (YYMMDD)", dateOfExpiry, dateOfExpiryValid),
        MrzField(MrzFieldId.NATIONALITY, "Nationality", nationality),
        MrzField(MrzFieldId.PRIMARY_IDENTIFIER, "Primary identifier", primaryIdentifier),
        MrzField(MrzFieldId.SECONDARY_IDENTIFIER, "Secondary identifier", secondaryIdentifier),
        MrzField(MrzFieldId.COMPOSITE_CHECK, "Composite check digit", if (compositeValid) "valid" else "invalid", compositeValid),
    )

    companion object {
        private val WEIGHTS = intArrayOf(7, 3, 1)

        // ICAO 9303-3 4.9: weights 7, 3, 1; digits keep their value, A-Z map to 10-35, the filler '<' to 0
        fun checkDigit(data: String): Char {
            var sum = 0
            data.forEachIndexed { i, c ->
                val value = when (c) {
                    in '0'..'9' -> c - '0'
                    in 'A'..'Z' -> c - 'A' + 10
                    '<' -> 0
                    else -> throw IllegalArgumentException("MRZ contains a character outside A-Z, 0-9 and <")
                }
                sum += value * WEIGHTS[i % 3]
            }
            return '0' + sum % 10
        }

        fun parse(mrz: String): Mrz {
            val format = MrzFormat.entries.firstOrNull { it.lineLength * it.lineCount == mrz.length }
                ?: throw IllegalArgumentException("MRZ length ${mrz.length} is not TD1, TD2 or TD3")
            require(mrz.all { it in '0'..'9' || it in 'A'..'Z' || it == '<' }) {
                "MRZ contains a character outside A-Z, 0-9 and <"
            }
            val lines = mrz.chunked(format.lineLength)
            return if (format == MrzFormat.TD1) parseTd1(lines) else parseTd2Td3(format, lines)
        }

        // ICAO 9303-5 4.2.2
        private fun parseTd1(lines: List<String>): Mrz {
            val (l1, l2, l3) = lines
            val optional1 = l1.substring(15, 30)
            var number = l1.substring(5, 14)
            var numberCheck = l1[14]
            // ICAO 9303-5: a number longer than 9 characters continues in the optional data, followed by its check digit
            if (numberCheck == '<') {
                val extension = optional1.substringBefore('<')
                if (extension.isNotEmpty()) {
                    number += extension.dropLast(1)
                    numberCheck = extension.last()
                }
            }
            val (primary, secondary) = names(l3)
            return Mrz(
                format = MrzFormat.TD1,
                lines = lines,
                documentCode = l1.substring(0, 2).trimEnd('<'),
                issuingState = l1.substring(2, 5).trimEnd('<'),
                documentNumber = number.trimEnd('<'),
                documentNumberValid = checkDigit(number) == numberCheck,
                dateOfBirth = l2.substring(0, 6),
                dateOfBirthValid = checkDigit(l2.substring(0, 6)) == l2[6],
                sex = l2.substring(7, 8),
                dateOfExpiry = l2.substring(8, 14),
                dateOfExpiryValid = checkDigit(l2.substring(8, 14)) == l2[14],
                nationality = l2.substring(15, 18).trimEnd('<'),
                primaryIdentifier = primary,
                secondaryIdentifier = secondary,
                optionalData1 = optional1.trimEnd('<'),
                optionalData2 = l2.substring(18, 29).trimEnd('<'),
                optionalData1Valid = null,
                compositeValid = checkDigit(l1.substring(5, 30) + l2.substring(0, 7) + l2.substring(8, 15) +
                    l2.substring(18, 29)) == l2[29],
            )
        }

        // ICAO 9303-6 4.2.2 (TD2) and 9303-4 4.2.2 (TD3) share the layout of the second line up to offset 28
        private fun parseTd2Td3(format: MrzFormat, lines: List<String>): Mrz {
            val (l1, l2) = lines
            val last = l2.length - 1
            val (primary, secondary) = names(l1.substring(5))
            val optional = if (format == MrzFormat.TD3) l2.substring(28, 42) else l2.substring(28, last)
            val optionalValid = if (format == MrzFormat.TD3) {
                val check = l2[42]
                if (check == '<' && optional.all { it == '<' }) true else checkDigit(optional) == check
            } else {
                null
            }
            return Mrz(
                format = format,
                lines = lines,
                documentCode = l1.substring(0, 2).trimEnd('<'),
                issuingState = l1.substring(2, 5).trimEnd('<'),
                documentNumber = l2.substring(0, 9).trimEnd('<'),
                documentNumberValid = checkDigit(l2.substring(0, 9)) == l2[9],
                dateOfBirth = l2.substring(13, 19),
                dateOfBirthValid = checkDigit(l2.substring(13, 19)) == l2[19],
                sex = l2.substring(20, 21),
                dateOfExpiry = l2.substring(21, 27),
                dateOfExpiryValid = checkDigit(l2.substring(21, 27)) == l2[27],
                nationality = l2.substring(10, 13).trimEnd('<'),
                primaryIdentifier = primary,
                secondaryIdentifier = secondary,
                optionalData1 = optional.trimEnd('<'),
                optionalData2 = null,
                optionalData1Valid = optionalValid,
                compositeValid = checkDigit(l2.substring(0, 10) + l2.substring(13, 20) + l2.substring(21, last)) == l2[last],
            )
        }

        private fun names(field: String): Pair<String, String> {
            val parts = field.split("<<", limit = 2)
            val primary = parts[0].replace('<', ' ').trim()
            val secondary = parts.getOrNull(1)?.replace('<', ' ')?.trim().orEmpty()
            return primary to secondary
        }
    }
}
