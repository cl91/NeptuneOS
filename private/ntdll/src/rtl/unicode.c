/*
 * This is taken shamelessly from ReactOS (which steals from WINE).
 */

#include <wchar.h>
#include "rtlp.h"

/*
 * @implemented
 *
 * NOTES
 *  If source is NULL the length of source is assumed to be 0.
 */
VOID NTAPI RtlInitUnicodeString(IN OUT PUNICODE_STRING DestinationString,
				IN PCWSTR SourceString)
{
    SIZE_T Size;
    CONST SIZE_T MaxSize = (MAXUSHORT & ~1) - sizeof(UNICODE_NULL); // an even number

    if (SourceString) {
        Size = wcslen(SourceString) * sizeof(WCHAR);
        __analysis_assume(Size <= MaxSize);

        if (Size > MaxSize) {
            Size = MaxSize;
	}
        DestinationString->Length = (USHORT)Size;
        DestinationString->MaximumLength = (USHORT)Size + sizeof(UNICODE_NULL);
    } else {
        DestinationString->Length = 0;
        DestinationString->MaximumLength = 0;
    }

    DestinationString->Buffer = (PWCHAR)SourceString;
}

/*
 * @implemented
 */
NTSTATUS NTAPI RtlInitUnicodeStringEx(OUT PUNICODE_STRING DestinationString,
				      IN PCWSTR SourceString)
{
    SIZE_T Size;
    CONST SIZE_T MaxSize = (MAXUSHORT & ~1) - sizeof(WCHAR); // an even number

    if (SourceString) {
        Size = wcslen(SourceString) * sizeof(WCHAR);
        if (Size > MaxSize) {
	    return STATUS_NAME_TOO_LONG;
	}
        DestinationString->Length = (USHORT)Size;
        DestinationString->MaximumLength = (USHORT)Size + sizeof(WCHAR);
    } else {
        DestinationString->Length = 0;
        DestinationString->MaximumLength = 0;
    }

    DestinationString->Buffer = (PWCHAR)SourceString;
    return STATUS_SUCCESS;
}

/*
 * @implemented
 *
 * NOTES
 *  If source is NULL the length of source is assumed to be 0.
 */
NTAPI VOID RtlInitAnsiString(IN OUT PANSI_STRING DestinationString,
			     IN PCSZ SourceString)
{
    SIZE_T Size;

    if (SourceString) {
        Size = strlen(SourceString);
        if (Size > (MAXUSHORT - sizeof(CHAR))) {
            Size = MAXUSHORT - sizeof(CHAR);
	}
        DestinationString->Length = (USHORT) Size;
        DestinationString->MaximumLength = (USHORT) Size + sizeof(CHAR);
    } else {
        DestinationString->Length = 0;
        DestinationString->MaximumLength = 0;
    }

    DestinationString->Buffer = (PCHAR) SourceString;
}

/*
 * @implemented
 */
NTAPI NTSTATUS RtlInitAnsiStringEx(IN OUT PANSI_STRING DestinationString,
				   IN PCSZ SourceString)
{
    SIZE_T Size;

    if (SourceString) {
        Size = strlen(SourceString);
        if (Size > (MAXUSHORT - sizeof(CHAR))) {
            return STATUS_NAME_TOO_LONG;
	}
        DestinationString->Length = (USHORT) Size;
        DestinationString->MaximumLength = (USHORT) Size + sizeof(CHAR);
    } else {
        DestinationString->Length = 0;
        DestinationString->MaximumLength = 0;
    }

    DestinationString->Buffer = (PCHAR) SourceString;
    return STATUS_SUCCESS;
}

/**************************************************************************
 *      RtlCharToInteger   (NTDLL.@)
 * @implemented
 * Converts a character string into its integer equivalent.
 *
 * RETURNS
 *  Success: STATUS_SUCCESS. value contains the converted number
 *  Failure: STATUS_INVALID_PARAMETER, if base is not 0, 2, 8, 10 or 16.
 *           STATUS_ACCESS_VIOLATION, if value is NULL.
 *
 * NOTES
 *  For base 0 it uses 10 as base and the string should be in the format
 *      "{whitespace} [+|-] [0[x|o|b]] {digits}".
 *  For other bases the string should be in the format
 *      "{whitespace} [+|-] {digits}".
 *  No check is made for value overflow, only the lower 32 bits are assigned.
 *  If str is NULL it crashes, as the native function does.
 *
 * DIFFERENCES
 *  This function does not read garbage behind '\0' as the native version does.
 */
NTSTATUS NTAPI RtlCharToInteger(PCSZ str, /* [I] '\0' terminated single-byte string containing a number */
                                ULONG base, /* [I] Number base for conversion (allowed 0, 2, 8, 10 or 16) */
                                PULONG value) /* [O] Destination for the converted value */
{
    CHAR chCurrent;
    int digit;
    ULONG RunningTotal = 0;
    char bMinus = 0;

    /* skip leading whitespaces */
    while (*str != '\0' && *str <= ' ')
        str++;

    /* Check for +/- */
    if (*str == '+') {
        str++;
    } else if (*str == '-') {
        bMinus = 1;
        str++;
    }

    /* base = 0 means autobase */
    if (base == 0) {
        base = 10;

        if (str[0] == '0') {
            if (str[1] == 'b') {
                str += 2;
                base = 2;
            } else if (str[1] == 'o') {
                str += 2;
                base = 8;
            } else if (str[1] == 'x') {
                str += 2;
                base = 16;
            }
        }
    } else if (base != 2 && base != 8 && base != 10 && base != 16) {
        return STATUS_INVALID_PARAMETER;
    }

    if (value == NULL)
        return STATUS_ACCESS_VIOLATION;

    while (*str != '\0') {
        chCurrent = *str;

        if (chCurrent >= '0' && chCurrent <= '9') {
            digit = chCurrent - '0';
        } else if (chCurrent >= 'A' && chCurrent <= 'Z') {
            digit = chCurrent - 'A' + 10;
        } else if (chCurrent >= 'a' && chCurrent <= 'z') {
            digit = chCurrent - 'a' + 10;
        } else {
            digit = -1;
        }

        if (digit < 0 || digit >= (int) base)
            break;

        RunningTotal = RunningTotal * base + digit;
        str++;
    }

    *value = bMinus ? (0 - RunningTotal) : RunningTotal;
    return STATUS_SUCCESS;
}

/*
 * @implemented
 */
VOID NTAPI RtlFreeUnicodeString(IN PUNICODE_STRING UnicodeString)
{
    if (UnicodeString->Buffer) {
	RtlFreeHeap(RtlGetProcessHeap(), 0, UnicodeString->Buffer);
        RtlZeroMemory(UnicodeString, sizeof(UNICODE_STRING));
    }
}

/*
 * @implemented
 */
NTAPI LONG RtlCompareUnicodeString(IN PCUNICODE_STRING s1,
				   IN PCUNICODE_STRING s2,
				   IN BOOLEAN CaseInsensitive)
{
    unsigned int len;
    LONG ret = 0;
    PCWSTR p1, p2;

    len = min(s1->Length, s2->Length) / sizeof(WCHAR);
    p1 = s1->Buffer;
    p2 = s2->Buffer;

    if (CaseInsensitive) {
        while (!ret && len--) {
	    ret = RtlpUpcaseUnicodeChar(*p1++) - RtlpUpcaseUnicodeChar(*p2++);
	}
    } else {
        while (!ret && len--) {
	    ret = *p1++ - *p2++;
	}
    }

    if (!ret) {
	ret = s1->Length - s2->Length;
    }

    return ret;
}

/*
 * @implemented
 *
 * RETURNS
 *  TRUE if strings are equal.
 */
NTAPI BOOLEAN RtlEqualUnicodeString(IN CONST UNICODE_STRING *s1,
				    IN CONST UNICODE_STRING *s2,
				    IN BOOLEAN CaseInsensitive)
{
    if (s1->Length != s2->Length) {
	return FALSE;
    }
    return !RtlCompareUnicodeString(s1, s2, CaseInsensitive);
}


/******************************************************************************
 * RtlUTF8ToUnicodeN [NTDLL.@]
 */
NTSTATUS NTAPI RtlUTF8ToUnicodeN(WCHAR *uni_dest, ULONG uni_bytes_max,
                                 ULONG *uni_bytes_written,
                                 const CHAR *utf8_src, ULONG utf8_bytes)
{
    NTSTATUS status;
    ULONG i, j;
    ULONG written;
    ULONG ch;
    ULONG utf8_trail_bytes;
    WCHAR utf16_ch[3];
    ULONG utf16_ch_len;

    if (!utf8_src)
        return STATUS_INVALID_PARAMETER_4;
    if (!uni_bytes_written)
        return STATUS_INVALID_PARAMETER;

    written = 0;
    status = STATUS_SUCCESS;

    for (i = 0; i < utf8_bytes; i++)
    {
        /* read UTF-8 lead byte */
        ch = (BYTE)utf8_src[i];
        utf8_trail_bytes = 0;
        if (ch >= 0xf5)
        {
            ch = 0xfffd;
            status = STATUS_SOME_NOT_MAPPED;
        }
        else if (ch >= 0xf0)
        {
            ch &= 0x07;
            utf8_trail_bytes = 3;
        }
        else if (ch >= 0xe0)
        {
            ch &= 0x0f;
            utf8_trail_bytes = 2;
        }
        else if (ch >= 0xc2)
        {
            ch &= 0x1f;
            utf8_trail_bytes = 1;
        }
        else if (ch >= 0x80)
        {
            /* overlong or trail byte */
            ch = 0xfffd;
            status = STATUS_SOME_NOT_MAPPED;
        }

        /* read UTF-8 trail bytes */
        if (i + utf8_trail_bytes < utf8_bytes)
        {
            for (j = 0; j < utf8_trail_bytes; j++)
            {
                if ((utf8_src[i + 1] & 0xc0) == 0x80)
                {
                    ch <<= 6;
                    ch |= utf8_src[i + 1] & 0x3f;
                    i++;
                }
                else
                {
                    ch = 0xfffd;
                    utf8_trail_bytes = 0;
                    status = STATUS_SOME_NOT_MAPPED;
                    break;
                }
            }
        }
        else
        {
            ch = 0xfffd;
            utf8_trail_bytes = 0;
            status = STATUS_SOME_NOT_MAPPED;
            i = utf8_bytes;
        }

        /* encode ch as UTF-16 */
        if ((ch > 0x10ffff) ||
            (ch >= 0xd800 && ch <= 0xdfff) ||
            (utf8_trail_bytes == 2 && ch < 0x00800) ||
            (utf8_trail_bytes == 3 && ch < 0x10000))
        {
            /* invalid codepoint or overlong encoding */
            utf16_ch[0] = 0xfffd;
            utf16_ch[1] = 0xfffd;
            utf16_ch[2] = 0xfffd;
            utf16_ch_len = utf8_trail_bytes;
            status = STATUS_SOME_NOT_MAPPED;
        }
        else if (ch >= 0x10000)
        {
            /* surrogate pair */
            ch -= 0x010000;
            utf16_ch[0] = 0xd800 + (ch >> 10 & 0x3ff);
            utf16_ch[1] = 0xdc00 + (ch >>  0 & 0x3ff);
            utf16_ch_len = 2;
        }
        else
        {
            /* single unit */
            utf16_ch[0] = ch;
            utf16_ch_len = 1;
        }

        if (!uni_dest)
        {
            written += utf16_ch_len;
            continue;
        }

        for (j = 0; j < utf16_ch_len; j++)
        {
            if (uni_bytes_max >= sizeof(WCHAR))
            {
                *uni_dest++ = utf16_ch[j];
                uni_bytes_max -= sizeof(WCHAR);
                written++;
            }
            else
            {
                uni_bytes_max = 0;
                status = STATUS_BUFFER_TOO_SMALL;
            }
        }
    }

    *uni_bytes_written = written * sizeof(WCHAR);
    return status;
}
