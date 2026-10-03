/*
 * PROJECT:     LiberNT CRT
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Bounds-checked (secure) narrow-string copy/concat functions.
 */

#include <stddef.h>

typedef size_t crt_size_t;
typedef int crt_errno_t;

#define CRT_EINVAL    22
#define CRT_ERANGE    34
#define CRT_STRUNCATE 80
#define CRT_TRUNCATE  ((crt_size_t)-1)

crt_errno_t __cdecl strcpy_s(char *dest, crt_size_t destsz, const char *src)
{
    crt_size_t i;
    if (dest == 0 || destsz == 0) return CRT_EINVAL;
    if (src == 0) { dest[0] = 0; return CRT_EINVAL; }
    for (i = 0; i < destsz; i++) { dest[i] = src[i]; if (src[i] == 0) return 0; }
    dest[0] = 0;
    return CRT_ERANGE;
}

crt_errno_t __cdecl strncpy_s(char *dest, crt_size_t destsz, const char *src, crt_size_t count)
{
    crt_size_t i;
    if (dest == 0 || destsz == 0) return CRT_EINVAL;
    if (src == 0) { dest[0] = 0; return (count == 0) ? 0 : CRT_EINVAL; }

    /* _TRUNCATE: copy what fits and report truncation (never overflow-fail). */
    if (count == CRT_TRUNCATE)
    {
        for (i = 0; i + 1 < destsz && src[i] != 0; i++) dest[i] = src[i];
        dest[i] = 0;
        return (src[i] != 0) ? CRT_STRUNCATE : 0;
    }

    /* Fixed count: a copy that would not fit (with its terminator) is ERANGE. */
    for (i = 0; i < count && src[i] != 0; i++)
    {
        if (i >= destsz) { dest[0] = 0; return CRT_ERANGE; }
        dest[i] = src[i];
    }
    if (i >= destsz) { dest[0] = 0; return CRT_ERANGE; }
    dest[i] = 0;
    return 0;
}

crt_errno_t __cdecl strcat_s(char *dest, crt_size_t destsz, const char *src)
{
    crt_size_t len, i;
    if (dest == 0 || destsz == 0) return CRT_EINVAL;
    for (len = 0; len < destsz && dest[len]; len++) ;
    if (len == destsz) { dest[0] = 0; return CRT_EINVAL; }
    if (src == 0) { dest[0] = 0; return CRT_EINVAL; }
    for (i = 0; len < destsz; i++, len++) { dest[len] = src[i]; if (src[i] == 0) return 0; }
    dest[0] = 0;
    return CRT_ERANGE;
}

crt_errno_t __cdecl strncat_s(char *dest, crt_size_t destsz, const char *src, crt_size_t count)
{
    crt_size_t len, i;
    if (dest == 0 || destsz == 0) return CRT_EINVAL;
    for (len = 0; len < destsz && dest[len]; len++) ;
    if (len == destsz) { dest[0] = 0; return CRT_EINVAL; }
    if (src == 0) { dest[0] = 0; return (count == 0) ? 0 : CRT_EINVAL; }

    /* _TRUNCATE: append what fits and report truncation. */
    if (count == CRT_TRUNCATE)
    {
        for (i = 0; len + 1 < destsz && src[i] != 0; i++, len++) dest[len] = src[i];
        dest[len] = 0;
        return (src[i] != 0) ? CRT_STRUNCATE : 0;
    }

    /* Fixed count: an append that would not fit (with its terminator) is ERANGE. */
    for (i = 0; i < count && src[i] != 0; i++, len++)
    {
        if (len >= destsz) { dest[0] = 0; return CRT_ERANGE; }
        dest[len] = src[i];
    }
    if (len >= destsz) { dest[0] = 0; return CRT_ERANGE; }
    dest[len] = 0;
    return 0;
}
