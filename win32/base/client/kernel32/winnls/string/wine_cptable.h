/*
 * Wine internal Unicode definitions
 *
 * Copyright 2000 Alexandre Julliard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#pragma once

#include <ctype.h>
#include <stdarg.h>
#include <string.h>

/* code page info common to SBCS and DBCS */
struct cp_info {
    unsigned int codepage; /* codepage id */
    unsigned int char_size; /* char size (1 or 2 bytes) */
    WCHAR def_char; /* default char value (can be double-byte) */
    WCHAR def_unicode_char; /* default Unicode char value */
    const char *name; /* code page name */
};

struct sbcs_table {
    struct cp_info info;
    const WCHAR *cp2uni; /* code page -> Unicode map */
    const WCHAR *cp2uni_glyphs; /* code page -> Unicode map with glyph chars */
    const unsigned char *uni2cp_low; /* Unicode -> code page map */
    const unsigned short *uni2cp_high;
};

struct dbcs_table {
    struct cp_info info;
    const WCHAR *cp2uni; /* code page -> Unicode map */
    const unsigned char *cp2uni_leadbytes;
    const unsigned short *uni2cp_low; /* Unicode -> code page map */
    const unsigned short *uni2cp_high;
    unsigned char lead_bytes[12]; /* lead bytes ranges */
};

union cptable {
    struct cp_info info;
    struct sbcs_table sbcs;
    struct dbcs_table dbcs;
};

extern const union cptable *wine_cp_get_table(unsigned int codepage);
extern const union cptable *wine_cp_enum_table(unsigned int index);

extern int wine_cp_mbstowcs(const union cptable *table, int flags, const char *src,
			    int srclen, WCHAR *dst, int dstlen);
extern int wine_cp_wcstombs(const union cptable *table, int flags, const WCHAR *src,
			    int srclen, char *dst, int dstlen, const char *defchar,
			    int *used);
extern int wine_cpsymbol_mbstowcs(const char *src, int srclen, WCHAR *dst, int dstlen);
extern int wine_cpsymbol_wcstombs(const WCHAR *src, int srclen, char *dst, int dstlen);
extern int wine_utf8_mbstowcs(int flags, const char *src, int srclen, WCHAR *dst,
			      int dstlen);
extern int wine_utf8_wcstombs(int flags, const WCHAR *src, int srclen, char *dst,
			      int dstlen);

extern int wine_compare_string(int flags, const WCHAR *str1, int len1, const WCHAR *str2,
			       int len2);
extern int wine_get_sortkey(int flags, const WCHAR *src, int srclen, char *dst,
			    int dstlen);
extern int wine_fold_string(int flags, const WCHAR *src, int srclen, WCHAR *dst,
			    int dstlen);
