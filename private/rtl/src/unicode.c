#include <nt.h>
#include <string.h>

#define assert(x)

/******************************************************************************
 * RtlUnicodeToUTF8N [NTDLL.@]
 */
NTSTATUS NTAPI RtlUnicodeToUTF8N(CHAR *utf8_dest, ULONG utf8_bytes_max,
                                 ULONG *utf8_bytes_written,
                                 const WCHAR *uni_src, ULONG uni_bytes)
{
    NTSTATUS status;
    ULONG i;
    ULONG written;
    ULONG ch;
    BYTE utf8_ch[4];
    ULONG utf8_ch_len;

    if (!uni_src)
        return STATUS_INVALID_PARAMETER_4;
    if (!utf8_bytes_written)
        return STATUS_INVALID_PARAMETER;
    if (utf8_dest && uni_bytes % sizeof(WCHAR))
        return STATUS_INVALID_PARAMETER_5;

    written = 0;
    status = STATUS_SUCCESS;

    for (i = 0; i < uni_bytes / sizeof(WCHAR); i++) {
        /* decode UTF-16 into ch */
        ch = uni_src[i];
        if (ch >= 0xdc00 && ch <= 0xdfff) {
            ch = 0xfffd;
            status = STATUS_SOME_NOT_MAPPED;
        } else if (ch >= 0xd800 && ch <= 0xdbff) {
            if (i + 1 < uni_bytes / sizeof(WCHAR)) {
                ch -= 0xd800;
                ch <<= 10;
                if (uni_src[i + 1] >= 0xdc00 && uni_src[i + 1] <= 0xdfff) {
                    ch |= uni_src[i + 1] - 0xdc00;
                    ch += 0x010000;
                    i++;
                } else {
                    ch = 0xfffd;
                    status = STATUS_SOME_NOT_MAPPED;
                }
            } else {
                ch = 0xfffd;
                status = STATUS_SOME_NOT_MAPPED;
            }
        }

        /* encode ch as UTF-8 */
        assert(ch <= 0x10ffff);
        if (ch < 0x80) {
            utf8_ch[0] = ch & 0x7f;
            utf8_ch_len = 1;
        } else if (ch < 0x800) {
            utf8_ch[0] = 0xc0 | (ch >>  6 & 0x1f);
            utf8_ch[1] = 0x80 | (ch >>  0 & 0x3f);
            utf8_ch_len = 2;
        } else if (ch < 0x10000) {
            utf8_ch[0] = 0xe0 | (ch >> 12 & 0x0f);
            utf8_ch[1] = 0x80 | (ch >>  6 & 0x3f);
            utf8_ch[2] = 0x80 | (ch >>  0 & 0x3f);
            utf8_ch_len = 3;
        } else if (ch < 0x200000) {
            utf8_ch[0] = 0xf0 | (ch >> 18 & 0x07);
            utf8_ch[1] = 0x80 | (ch >> 12 & 0x3f);
            utf8_ch[2] = 0x80 | (ch >>  6 & 0x3f);
            utf8_ch[3] = 0x80 | (ch >>  0 & 0x3f);
            utf8_ch_len = 4;
        }

        if (!utf8_dest) {
            written += utf8_ch_len;
            continue;
        }

        if (utf8_bytes_max >= utf8_ch_len) {
            memcpy(utf8_dest, utf8_ch, utf8_ch_len);
            utf8_dest += utf8_ch_len;
            utf8_bytes_max -= utf8_ch_len;
            written += utf8_ch_len;
        } else {
            utf8_bytes_max = 0;
            status = STATUS_BUFFER_TOO_SMALL;
        }
    }

    *utf8_bytes_written = written;
    return status;
}
