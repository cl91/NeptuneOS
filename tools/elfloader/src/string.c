/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <strops.h>
#include <printf.h>
#include <abort.h>

#define BYTE_PER_WORD   sizeof(word_t)

/* Both memset and memcpy need a custom type that allows us to use a word
 * that has the aliasing properties of a char.
 */
#ifdef __GNUC__
#define HAS_MAY_ALIAS
#elif defined(__clang__)
#if __has_attribute(may_alias)
#define HAS_MAY_ALIAS
#endif
#endif

#ifdef HAS_MAY_ALIAS
typedef word_t __attribute__((__may_alias__)) u_alias;
#endif

size_t strlen(const char *str)
{
    const char *s;
    for (s = str; *s; ++s);
    return (s - str);
}

int strcmp(const char *a, const char *b)
{
    while (1) {
        if (*a != * b) {
            return ((unsigned char) * a) - ((unsigned char) * b);
        }
        if (*a == 0) {
            return 0;
        }
        a++;
        b++;
    }
}

int strncmp(const char *s1, const char *s2, size_t n)
{
    word_t i;
    int diff;

    for (i = 0; i < n; i++) {
        diff = ((unsigned char *)s1)[i] - ((unsigned char *)s2)[i];
        if (diff != 0 || s1[i] == '\0') {
            return diff;
        }
    }

    return 0;
}

void *memset(void *s, int c, size_t n)
{
    char *mem = (char *)s;

#ifdef HAS_MAY_ALIAS
    /* fill byte by byte until word aligned */
    for (; (uintptr_t)mem % BYTE_PER_WORD != 0 && n > 0; mem++, n--) {
        *mem = c;
    }
    /* construct word filler with some smart math magic that works for any
     * byte size actually. Assume words have 3 byte, then 0xffffff / 0xff is
     * 0x010101, and 0x010101 * 0xab is 0xababab  */
    u_alias fill = (((u_alias)(-1)) / 0xff) * (unsigned char)c;
    /* do as many word writes as we can */
    for (; n > BYTE_PER_WORD - 1; n -= BYTE_PER_WORD, mem += BYTE_PER_WORD) {
        *(u_alias *)mem = fill;
    }
    /* fill byte by byte for any remainder */
    for (; n > 0; n--, mem++) {
        *mem = c;
    }
#else
    /* Without the __may__alias__ attribute we cannot safely do word writes
     * so fallback to bytes */
    size_t i;
    for (i = 0; i < n; i++) {
        mem[i] = c;
    }
#endif

    return s;
}

void *memmove(void *restrict dest, const void *restrict src, size_t n)
{
    unsigned char *d = (unsigned char *)dest;
    const unsigned char *s = (const unsigned char *)src;

    /* no copying to do */
    if (d == s) {
        return dest;
    }
    /* for non-overlapping regions, just use memcpy */
    else if (s + n <= d || d + n <= s) {
        return memcpy(dest, src, n);
    }
    /* if copying from the start of s to the start of d, just use memcpy */
    else if (s > d) {
        return memcpy(dest, src, n);
    }

    /* copy from end of 's' to end of 'd' */
    size_t i;
    for (i = 1; i <= n; i++) {
        d[n - i] = s[n - i];
    }

    return dest;
}

void *memcpy(void *restrict dest, const void *restrict src, size_t n)
{
    unsigned char *d = (unsigned char *)dest;
    const unsigned char *s = (const unsigned char *)src;

    /* For ARM, we also need to consider if src is aligned.           *
     * There are two cases: (1) If rs == 0 and rd == 0, dest          *
     * and src are copy_unit-aligned. (2) If (rs == rd && rs != 0),   *
     * src and dest can be made copy_unit-aligned by copying rs bytes *
     * first. (1) is a special case of (2).                           */

    size_t copy_unit = BYTE_PER_WORD;
    while (1) {
        int rs = (uintptr_t)s % copy_unit;
        int rd = (uintptr_t)d % copy_unit;
        if (rs == rd) {
            break;
        }
        if (copy_unit == 1) {
            break;
        }
        copy_unit >>= 1;
    }

#ifdef HAS_MAY_ALIAS
    /* copy byte by byte until copy-unit aligned */
    for (; (uintptr_t)d % copy_unit != 0 && n > 0; d++, s++, n--) {
        *d = *s;
    }
    /* copy unit by unit as long as we can */
    for (; n > copy_unit - 1; n -= copy_unit, s += copy_unit, d += copy_unit) {
        switch (copy_unit) {
        case 8:
            *(uint64_t *)d = *(const uint64_t *)s;
            break;
        case 4:
            *(uint32_t *)d = *(const uint32_t *)s;
            break;
        case 2:
            *(uint16_t *)d = *(const uint16_t *)s;
            break;
        case 1:
            *(uint8_t *)d = *(const uint8_t *)s;
            break;
        default:
            printf("Invalid copy unit %ld\n", copy_unit);
            abort();
        }
    }
    /* copy any remainder byte by byte */
    for (; n > 0; d++, s++, n--) {
        *d = *s;
    }
#else
    size_t i;
    for (i = 0; i < n; i++) {
        d[i] = s[i];
    }
#endif

    return dest;
}
