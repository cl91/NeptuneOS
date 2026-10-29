/*
 * Unicode sort key generation
 *
 * Copyright 2003 Dmitry Timoshkov
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
#include "wine_unicode.h"

extern unsigned int WineDecompose(WCHAR Ch, WCHAR *Dst, unsigned int Dstlen);
extern const unsigned int CollationTable[];

/*
 * flags - normalization NORM_* flags
 *
 * FIXME: 'variable' flag not handled
 */
int WineGetSortkey(int Flags, const WCHAR *Src, int Srclen, char *Dst, int Dstlen)
{
    WCHAR Dummy[4]; /* no decomposition is larger than 4 chars */
    int KeyLen[4];
    char *KeyPtr[4];
    const WCHAR *SrcSave = Src;
    int SrclenSave = Srclen;

    KeyLen[0] = KeyLen[1] = KeyLen[2] = KeyLen[3] = 0;
    for (; Srclen; Srclen--, Src++) {
	unsigned int i, DecomposedLen = 1; /*wine_decompose(*src, dummy, 4);*/
	Dummy[0] = *Src;
	if (DecomposedLen) {
	    for (i = 0; i < DecomposedLen; i++) {
		WCHAR Wch = Dummy[i];
		unsigned int Ce;

		/* tests show that win2k just ignores NORM_IGNORENONSPACE,
		 * and skips white space and punctuation characters for
		 * NORM_IGNORESYMBOLS.
		 */
		if ((Flags & NORM_IGNORESYMBOLS) &&
		    (GetCharTypeW(Wch) & (C1_PUNCT | C1_SPACE)))
		    continue;

		if (Flags & NORM_IGNORECASE)
		    Wch = tolowerW(Wch);

		Ce = CollationTable[CollationTable[Wch >> 8] + (Wch & 0xff)];
		if (Ce != (unsigned int)-1) {
		    if (Ce >> 16)
			KeyLen[0] += 2;
		    if ((Ce >> 8) & 0xff)
			KeyLen[1]++;
		    if ((Ce >> 4) & 0x0f)
			KeyLen[2]++;
		    if (Ce & 1) {
			if (Wch >> 8)
			    KeyLen[3]++;
			KeyLen[3]++;
		    }
		} else {
		    KeyLen[0] += 2;
		    if (Wch >> 8)
			KeyLen[0]++;
		    if (Wch & 0xff)
			KeyLen[0]++;
		}
	    }
	}
    }

    if (!Dstlen) /* compute length */
	/* 4 * '\1' + 1 * '\0' + key length */
	return KeyLen[0] + KeyLen[1] + KeyLen[2] + KeyLen[3] + 4 + 1;

    if (Dstlen < KeyLen[0] + KeyLen[1] + KeyLen[2] + KeyLen[3] + 4 + 1)
	return 0; /* overflow */

    Src = SrcSave;
    Srclen = SrclenSave;

    KeyPtr[0] = Dst;
    KeyPtr[1] = KeyPtr[0] + KeyLen[0] + 1;
    KeyPtr[2] = KeyPtr[1] + KeyLen[1] + 1;
    KeyPtr[3] = KeyPtr[2] + KeyLen[2] + 1;

    for (; Srclen; Srclen--, Src++) {
	unsigned int i, DecomposedLen = 1; /*wine_decompose(*src, dummy, 4);*/
	Dummy[0] = *Src;
	if (DecomposedLen) {
	    for (i = 0; i < DecomposedLen; i++) {
		WCHAR Wch = Dummy[i];
		unsigned int Ce;

		/* tests show that win2k just ignores NORM_IGNORENONSPACE,
		 * and skips white space and punctuation characters for
		 * NORM_IGNORESYMBOLS.
		 */
		if ((Flags & NORM_IGNORESYMBOLS) &&
		    (GetCharTypeW(Wch) & (C1_PUNCT | C1_SPACE)))
		    continue;

		if (Flags & NORM_IGNORECASE)
		    Wch = tolowerW(Wch);

		Ce = CollationTable[CollationTable[Wch >> 8] + (Wch & 0xff)];
		if (Ce != (unsigned int)-1) {
		    WCHAR Key;
		    if ((Key = Ce >> 16)) {
			*KeyPtr[0]++ = Key >> 8;
			*KeyPtr[0]++ = Key & 0xff;
		    }
		    /* make key 1 start from 2 */
		    if ((Key = (Ce >> 8) & 0xff))
			*KeyPtr[1]++ = Key + 1;
		    /* make key 2 start from 2 */
		    if ((Key = (Ce >> 4) & 0x0f))
			*KeyPtr[2]++ = Key + 1;
		    /* key 3 is always a character code */
		    if (Ce & 1) {
			if (Wch >> 8)
			    *KeyPtr[3]++ = Wch >> 8;
			if (Wch & 0xff)
			    *KeyPtr[3]++ = Wch & 0xff;
		    }
		} else {
		    *KeyPtr[0]++ = 0xff;
		    *KeyPtr[0]++ = 0xfe;
		    if (Wch >> 8)
			*KeyPtr[0]++ = Wch >> 8;
		    if (Wch & 0xff)
			*KeyPtr[0]++ = Wch & 0xff;
		}
	    }
	}
    }

    *KeyPtr[0] = '\1';
    *KeyPtr[1] = '\1';
    *KeyPtr[2] = '\1';
    *KeyPtr[3]++ = '\1';
    *KeyPtr[3] = 0;

    return KeyPtr[3] - Dst;
}

static inline int CompareUnicodeWeights(int Flags, const WCHAR *Str1, int Len1,
					  const WCHAR *Str2, int Len2)
{
    unsigned int Ce1, Ce2;
    int Ret;

    /* 32-bit collation element table format:
     * unicode weight - high 16 bit, diacritic weight - high 8 bit of low 16 bit,
     * case weight - high 4 bit of low 8 bit.
     */
    while (Len1 > 0 && Len2 > 0) {
	if (Flags & NORM_IGNORESYMBOLS) {
	    int Skip = 0;
	    /* FIXME: not tested */
	    if (GetCharTypeW(*Str1) & (C1_PUNCT | C1_SPACE)) {
		Str1++;
		Len1--;
		Skip = 1;
	    }
	    if (GetCharTypeW(*Str2) & (C1_PUNCT | C1_SPACE)) {
		Str2++;
		Len2--;
		Skip = 1;
	    }
	    if (Skip)
		continue;
	}

	/* hyphen and apostrophe are treated differently depending on
	 * whether SORT_STRINGSORT specified or not
	 */
	if (!(Flags & SORT_STRINGSORT)) {
	    if (*Str1 == '-' || *Str1 == '\'') {
		if (*Str2 != '-' && *Str2 != '\'') {
		    Str1++;
		    Len1--;
		    continue;
		}
	    } else if (*Str2 == '-' || *Str2 == '\'') {
		Str2++;
		Len2--;
		continue;
	    }
	}

	Ce1 = CollationTable[CollationTable[*Str1 >> 8] + (*Str1 & 0xff)];
	Ce2 = CollationTable[CollationTable[*Str2 >> 8] + (*Str2 & 0xff)];

	if (Ce1 != (unsigned int)-1 && Ce2 != (unsigned int)-1)
	    Ret = (Ce1 >> 16) - (Ce2 >> 16);
	else
	    Ret = *Str1 - *Str2;

	if (Ret)
	    return Ret;

	Str1++;
	Str2++;
	Len1--;
	Len2--;
    }
    while (Len1 && !*Str1) {
	Str1++;
	Len1--;
    }
    while (Len2 && !*Str2) {
	Str2++;
	Len2--;
    }
    return Len1 - Len2;
}

static inline int CompareDiacriticWeights(int Flags, const WCHAR *Str1, int Len1,
					    const WCHAR *Str2, int Len2)
{
    unsigned int Ce1, Ce2;
    int Ret;

    /* 32-bit collation element table format:
     * unicode weight - high 16 bit, diacritic weight - high 8 bit of low 16 bit,
     * case weight - high 4 bit of low 8 bit.
     */
    while (Len1 > 0 && Len2 > 0) {
	if (Flags & NORM_IGNORESYMBOLS) {
	    int Skip = 0;
	    /* FIXME: not tested */
	    if (GetCharTypeW(*Str1) & (C1_PUNCT | C1_SPACE)) {
		Str1++;
		Len1--;
		Skip = 1;
	    }
	    if (GetCharTypeW(*Str2) & (C1_PUNCT | C1_SPACE)) {
		Str2++;
		Len2--;
		Skip = 1;
	    }
	    if (Skip)
		continue;
	}

	Ce1 = CollationTable[CollationTable[*Str1 >> 8] + (*Str1 & 0xff)];
	Ce2 = CollationTable[CollationTable[*Str2 >> 8] + (*Str2 & 0xff)];

	if (Ce1 != (unsigned int)-1 && Ce2 != (unsigned int)-1)
	    Ret = ((Ce1 >> 8) & 0xff) - ((Ce2 >> 8) & 0xff);
	else
	    Ret = *Str1 - *Str2;

	if (Ret)
	    return Ret;

	Str1++;
	Str2++;
	Len1--;
	Len2--;
    }
    while (Len1 && !*Str1) {
	Str1++;
	Len1--;
    }
    while (Len2 && !*Str2) {
	Str2++;
	Len2--;
    }
    return Len1 - Len2;
}

static inline int CompareCaseWeights(int Flags, const WCHAR *Str1, int Len1,
				       const WCHAR *Str2, int Len2)
{
    unsigned int Ce1, Ce2;
    int Ret;

    /* 32-bit collation element table format:
     * unicode weight - high 16 bit, diacritic weight - high 8 bit of low 16 bit,
     * case weight - high 4 bit of low 8 bit.
     */
    while (Len1 > 0 && Len2 > 0) {
	if (Flags & NORM_IGNORESYMBOLS) {
	    int Skip = 0;
	    /* FIXME: not tested */
	    if (GetCharTypeW(*Str1) & (C1_PUNCT | C1_SPACE)) {
		Str1++;
		Len1--;
		Skip = 1;
	    }
	    if (GetCharTypeW(*Str2) & (C1_PUNCT | C1_SPACE)) {
		Str2++;
		Len2--;
		Skip = 1;
	    }
	    if (Skip)
		continue;
	}

	Ce1 = CollationTable[CollationTable[*Str1 >> 8] + (*Str1 & 0xff)];
	Ce2 = CollationTable[CollationTable[*Str2 >> 8] + (*Str2 & 0xff)];

	if (Ce1 != (unsigned int)-1 && Ce2 != (unsigned int)-1)
	    Ret = ((Ce1 >> 4) & 0x0f) - ((Ce2 >> 4) & 0x0f);
	else
	    Ret = *Str1 - *Str2;

	if (Ret)
	    return Ret;

	Str1++;
	Str2++;
	Len1--;
	Len2--;
    }
    while (Len1 && !*Str1) {
	Str1++;
	Len1--;
    }
    while (Len2 && !*Str2) {
	Str2++;
	Len2--;
    }
    return Len1 - Len2;
}

int WineCompareString(int Flags, const WCHAR *Str1, int Len1, const WCHAR *Str2,
			int Len2)
{
    int Ret;

    Ret = CompareUnicodeWeights(Flags, Str1, Len1, Str2, Len2);
    if (!Ret) {
	if (!(Flags & NORM_IGNORENONSPACE))
	    Ret = CompareDiacriticWeights(Flags, Str1, Len1, Str2, Len2);
	if (!Ret && !(Flags & NORM_IGNORECASE))
	    Ret = CompareCaseWeights(Flags, Str1, Len1, Str2, Len2);
    }
    return Ret;
}
