/*
 * Profile functions
 *
 * Copyright 1993 Miguel de Icaza
 * Copyright 1996 Alexandre Julliard
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

#include <k32.h>
DEBUG_CHANNEL(profile);

static const char BomUtf8[] = { 0xEF, 0xBB, 0xBF };

typedef enum {
    ENCODING_ANSI = 1,
    ENCODING_UTF8,
    ENCODING_UTF16LE,
    ENCODING_UTF16BE
} ENCODING;

typedef struct _PROFILEKEY {
    WCHAR *Value;
    struct _PROFILEKEY *Next;
    WCHAR Name[1];
} PROFILEKEY;

typedef struct _PROFILESECTION {
    PROFILEKEY *Key;
    struct _PROFILESECTION *Next;
    WCHAR Name[1];
} PROFILESECTION;

typedef struct {
    BOOL Changed;
    PROFILESECTION *Section;
    WCHAR *Filename;
    FILETIME LastWriteTime;
    ENCODING Encoding;
} PROFILE;

#define N_CACHED_PROFILES 10

/* Cached profile files */
static PROFILE *MRUProfile[N_CACHED_PROFILES] = { NULL };

#define CURRENT_PROFILE (MRUProfile[0])

/* Check for comments in profile */
#define IS_ENTRY_COMMENT(str) ((str)[0] == ';')

static const WCHAR EmptyStringW[] = { 0 };
static const WCHAR WininiW[] = { 'w', 'i', 'n', '.', 'i', 'n', 'i', 0 };

static RTL_CRITICAL_SECTION ProfileCritSect;
static RTL_CRITICAL_SECTION_DEBUG CritsectDebug = { 0,
						     0,
						     &ProfileCritSect,
						     { &CritsectDebug.ProcessLocksList,
						       &CritsectDebug.ProcessLocksList },
						     0,
						     0,
						     0 };
static RTL_CRITICAL_SECTION ProfileCritSect = { &CritsectDebug, -1, 0, 0, 0, 0 };

static const char Hex[16] = "0123456789ABCDEF";

/***********************************************************************
 *           PROFILE_CopyEntry
 *
 * Copy the content of an entry into a buffer, removing quotes, and possibly
 * translating environment variables.
 */
static void PROFILE_CopyEntry(LPWSTR Buffer, LPCWSTR Value, int Len, BOOL StripQuote)
{
    WCHAR Quote = '\0';

    if (!Buffer)
	return;

    if (StripQuote && ((*Value == '\'') || (*Value == '\"'))) {
	if (Value[1] && (Value[strlenW(Value) - 1] == *Value))
	    Quote = *Value++;
    }

    lstrcpynW(Buffer, Value, Len);
    if (Quote && (Len >= lstrlenW(Value)))
	Buffer[strlenW(Buffer) - 1] = '\0';
}

/* byte-swaps shorts in-place in a buffer. len is in WCHARs */
static inline void PROFILE_ByteSwapShortBuffer(WCHAR *Buffer, int Len)
{
    int i;
    USHORT *Shortbuffer = Buffer;
    for (i = 0; i < Len; i++)
	Shortbuffer[i] = RtlUshortByteSwap(Shortbuffer[i]);
}

/* writes any necessary encoding marker to the file */
static inline void PROFILE_WriteMarker(HANDLE hFile, ENCODING Encoding)
{
    DWORD dwBytesWritten;
    WCHAR Bom;
    switch (Encoding) {
    case ENCODING_ANSI:
	break;
    case ENCODING_UTF8:
	WriteFile(hFile, BomUtf8, sizeof(BomUtf8), &dwBytesWritten, NULL);
	break;
    case ENCODING_UTF16LE:
	Bom = 0xFEFF;
	WriteFile(hFile, &Bom, sizeof(Bom), &dwBytesWritten, NULL);
	break;
    case ENCODING_UTF16BE:
	Bom = 0xFFFE;
	WriteFile(hFile, &Bom, sizeof(Bom), &dwBytesWritten, NULL);
	break;
    }
}

static void PROFILE_WriteLine(HANDLE hFile, WCHAR *szLine, int Len, ENCODING Encoding)
{
    char *WriteBuffer;
    int WriteBufferLen;
    DWORD dwBytesWritten;

    TRACE("writing: %s\n", debugstr_wn(szLine, len));

    switch (Encoding) {
    case ENCODING_ANSI:
	WriteBufferLen = WideCharToMultiByte(CP_ACP, 0, szLine, Len, NULL, 0, NULL,
					       NULL);
	WriteBuffer = HeapAlloc(GetProcessHeap(), 0, WriteBufferLen);
	if (!WriteBuffer)
	    return;
	Len = WideCharToMultiByte(CP_ACP, 0, szLine, Len, WriteBuffer, WriteBufferLen,
				  NULL, NULL);
	WriteFile(hFile, WriteBuffer, Len, &dwBytesWritten, NULL);
	HeapFree(GetProcessHeap(), 0, WriteBuffer);
	break;
    case ENCODING_UTF8:
	WriteBufferLen = WideCharToMultiByte(CP_UTF8, 0, szLine, Len, NULL, 0, NULL,
					       NULL);
	WriteBuffer = HeapAlloc(GetProcessHeap(), 0, WriteBufferLen);
	if (!WriteBuffer)
	    return;
	Len = WideCharToMultiByte(CP_UTF8, 0, szLine, Len, WriteBuffer, WriteBufferLen,
				  NULL, NULL);
	WriteFile(hFile, WriteBuffer, Len, &dwBytesWritten, NULL);
	HeapFree(GetProcessHeap(), 0, WriteBuffer);
	break;
    case ENCODING_UTF16LE:
	WriteFile(hFile, szLine, Len * sizeof(WCHAR), &dwBytesWritten, NULL);
	break;
    case ENCODING_UTF16BE:
	PROFILE_ByteSwapShortBuffer(szLine, Len);
	WriteFile(hFile, szLine, Len * sizeof(WCHAR), &dwBytesWritten, NULL);
	break;
    default:
	FIXME("encoding type %d not implemented\n", encoding);
    }
}

/***********************************************************************
 *           PROFILE_Save
 *
 * Save a profile tree to a file.
 */
static void PROFILE_Save(HANDLE hFile, const PROFILESECTION *Section, ENCODING Encoding)
{
    PROFILEKEY *Key;
    WCHAR *Buffer, *p;

    PROFILE_WriteMarker(hFile, Encoding);

    for (; Section; Section = Section->Next) {
	int Len = 0;

	if (Section->Name[0])
	    Len += strlenW(Section->Name) + 4;

	for (Key = Section->Key; Key; Key = Key->Next) {
	    Len += strlenW(Key->Name) + 2;
	    if (Key->Value)
		Len += strlenW(Key->Value) + 1;
	}

	Buffer = HeapAlloc(GetProcessHeap(), 0, Len * sizeof(WCHAR));
	if (!Buffer)
	    return;

	p = Buffer;
	LONG RemainingLen = Len;
	assert(RemainingLen > 0);
	if (Section->Name[0]) {
	    *p++ = '[';
	    RemainingLen--;
	    assert(RemainingLen > 0);
	    wcscpy_s(p, RemainingLen, Section->Name);
	    LONG BufLen = strlenW(p);
	    RemainingLen -= BufLen + 3;
	    p += BufLen;
	    *p++ = ']';
	    *p++ = '\r';
	    *p++ = '\n';
	    assert(RemainingLen > 0);
	}

	for (Key = Section->Key; Key; Key = Key->Next) {
	    wcscpy_s(p, RemainingLen, Key->Name);
	    LONG BufLen = strlenW(p);
	    RemainingLen -= BufLen;
	    assert(RemainingLen > 0);
	    p += BufLen;
	    if (Key->Value) {
		*p++ = '=';
		RemainingLen--;
		assert(RemainingLen > 0);
		wcscpy_s(p, RemainingLen, Key->Value);
		BufLen = strlenW(p);
		RemainingLen -= BufLen;
		assert(RemainingLen > 0);
		p += BufLen;
	    }
	    RemainingLen -= 2;
	    assert(RemainingLen > 0);
	    *p++ = '\r';
	    *p++ = '\n';
	}
	PROFILE_WriteLine(hFile, Buffer, Len, Encoding);
	HeapFree(GetProcessHeap(), 0, Buffer);
    }
}

/***********************************************************************
 *           PROFILE_Free
 *
 * Free a profile tree.
 */
static void PROFILE_Free(PROFILESECTION *Section)
{
    PROFILESECTION *NextSection;
    PROFILEKEY *Key, *NextKey;

    for (; Section; Section = NextSection) {
	for (Key = Section->Key; Key; Key = NextKey) {
	    NextKey = Key->Next;
	    HeapFree(GetProcessHeap(), 0, Key->Value);
	    HeapFree(GetProcessHeap(), 0, Key);
	}
	NextSection = Section->Next;
	HeapFree(GetProcessHeap(), 0, Section);
    }
}

/* returns TRUE if a whitespace character, else FALSE */
static inline BOOL PROFILE_IsWideSpaceChar(WCHAR c)
{
    /* ^Z (DOS EOF) is a space too  (found on CD-ROMs) */
    return isspaceW(c) || c == 0x1a;
}

static inline ENCODING PROFILE_DetectTextEncoding(const void *Buffer, int *Len)
{
    int Flags = IS_TEXT_UNICODE_SIGNATURE | IS_TEXT_UNICODE_REVERSE_SIGNATURE |
		IS_TEXT_UNICODE_ODD_LENGTH;
    if (*Len >= sizeof(BomUtf8) && !memcmp(Buffer, BomUtf8, sizeof(BomUtf8))) {
	*Len = sizeof(BomUtf8);
	return ENCODING_UTF8;
    }
    RtlIsTextUnicode(Buffer, *Len, &Flags);
    if (Flags & IS_TEXT_UNICODE_SIGNATURE) {
	*Len = sizeof(WCHAR);
	return ENCODING_UTF16LE;
    }
    if (Flags & IS_TEXT_UNICODE_REVERSE_SIGNATURE) {
	*Len = sizeof(WCHAR);
	return ENCODING_UTF16BE;
    }
    *Len = 0;
    return ENCODING_ANSI;
}

/***********************************************************************
 *           PROFILE_Load
 *
 * Load a profile tree from a file.
 */
static PROFILESECTION *PROFILE_Load(HANDLE hFile, ENCODING *pEncoding)
{
    void *BufferBase, *pBuffer;
    WCHAR *szFile;
    const WCHAR *szLineStart, *szLineEnd;
    const WCHAR *szValueStart, *szEnd, *NextLine;
    int Len;
    PROFILESECTION *Section, *FirstSection;
    PROFILESECTION **NextSection;
    PROFILEKEY *Key, *PrevKey, **NextKey;
    DWORD dwFileSize;

    TRACE("%p\n", hFile);

    dwFileSize = GetFileSize(hFile, NULL);
    if (dwFileSize == INVALID_FILE_SIZE || dwFileSize == 0)
	return NULL;

    BufferBase = HeapAlloc(GetProcessHeap(), 0, dwFileSize);
    if (!BufferBase)
	return NULL;

    if (!ReadFile(hFile, BufferBase, dwFileSize, &dwFileSize, NULL)) {
	HeapFree(GetProcessHeap(), 0, BufferBase);
	WARN("Error %d reading file\n", GetLastError());
	return NULL;
    }
    Len = dwFileSize;
    *pEncoding = PROFILE_DetectTextEncoding(BufferBase, &Len);
    /* len is set to the number of bytes in the character marker.
     * we want to skip these bytes */
    pBuffer = (char *)BufferBase + Len;
    dwFileSize -= Len;
    switch (*pEncoding) {
    case ENCODING_ANSI:
	TRACE("ANSI encoding\n");

	Len = MultiByteToWideChar(CP_ACP, 0, pBuffer, dwFileSize, NULL, 0);
	szFile = HeapAlloc(GetProcessHeap(), 0, Len * sizeof(WCHAR));
	if (!szFile) {
	    HeapFree(GetProcessHeap(), 0, BufferBase);
	    return NULL;
	}
	MultiByteToWideChar(CP_ACP, 0, pBuffer, dwFileSize, szFile, Len);
	szEnd = szFile + Len;
	break;
    case ENCODING_UTF8:
	TRACE("UTF8 encoding\n");

	Len = MultiByteToWideChar(CP_UTF8, 0, pBuffer, dwFileSize, NULL, 0);
	szFile = HeapAlloc(GetProcessHeap(), 0, Len * sizeof(WCHAR));
	if (!szFile) {
	    HeapFree(GetProcessHeap(), 0, BufferBase);
	    return NULL;
	}
	MultiByteToWideChar(CP_UTF8, 0, pBuffer, dwFileSize, szFile, Len);
	szEnd = szFile + Len;
	break;
    case ENCODING_UTF16LE:
	TRACE("UTF16 Little Endian encoding\n");
	szFile = pBuffer;
	szEnd = (WCHAR *)((char *)pBuffer + dwFileSize);
	break;
    case ENCODING_UTF16BE:
	TRACE("UTF16 Big Endian encoding\n");
	szFile = pBuffer;
	szEnd = (WCHAR *)((char *)pBuffer + dwFileSize);
	PROFILE_ByteSwapShortBuffer(szFile, dwFileSize / sizeof(WCHAR));
	break;
    default:
	FIXME("encoding type %d not implemented\n", *pEncoding);
	HeapFree(GetProcessHeap(), 0, BufferBase);
	return NULL;
    }

    FirstSection = HeapAlloc(GetProcessHeap(), 0, sizeof(*Section));
    if (FirstSection == NULL) {
	if (szFile != pBuffer)
	    HeapFree(GetProcessHeap(), 0, szFile);
	HeapFree(GetProcessHeap(), 0, BufferBase);
	return NULL;
    }
    FirstSection->Name[0] = 0;
    FirstSection->Key = NULL;
    FirstSection->Next = NULL;
    NextSection = &FirstSection->Next;
    NextKey = &FirstSection->Key;
    PrevKey = NULL;
    NextLine = szFile;

    while (NextLine < szEnd) {
	szLineStart = NextLine;
	NextLine = memchrW(szLineStart, '\n', szEnd - szLineStart);
	if (!NextLine)
	    NextLine = memchrW(szLineStart, '\r', szEnd - szLineStart);
	if (!NextLine)
	    NextLine = szEnd;
	else
	    NextLine++;
	szLineEnd = NextLine;

	/* get rid of white space */
	while (szLineStart < szLineEnd && PROFILE_IsWideSpaceChar(*szLineStart))
	    szLineStart++;
	while ((szLineEnd > szLineStart) && PROFILE_IsWideSpaceChar(szLineEnd[-1]))
	    szLineEnd--;

	if (szLineStart >= szLineEnd)
	    continue;

	if (*szLineStart == '[') /* section start */
	{
	    const WCHAR *szSectionEnd;
	    if (!(szSectionEnd = memrchrW(szLineStart, ']', szLineEnd - szLineStart))) {
		WARN("Invalid section header at line %d: %s\n", line,
		     debugstr_wn(szLineStart, (int)(szLineEnd - szLineStart)));
	    } else {
		szLineStart++;
		Len = (int)(szSectionEnd - szLineStart);
		/* no need to allocate +1 for NULL terminating character as
		 * already included in structure */
		if (!(Section = HeapAlloc(GetProcessHeap(), 0,
					  sizeof(*Section) + Len * sizeof(WCHAR))))
		    break;
		memcpy(Section->Name, szLineStart, Len * sizeof(WCHAR));
		Section->Name[Len] = '\0';
		Section->Key = NULL;
		Section->Next = NULL;
		*NextSection = Section;
		NextSection = &Section->Next;
		NextKey = &Section->Key;
		PrevKey = NULL;

		TRACE("New section: %s\n", debugstr_w(section->name));

		continue;
	    }
	}

	/* get rid of white space after the name and before the start
	 * of the value */
	Len = szLineEnd - szLineStart;
	if ((szValueStart = memchrW(szLineStart, '=', szLineEnd - szLineStart)) != NULL) {
	    const WCHAR *szNameEnd = szValueStart;
	    while ((szNameEnd > szLineStart) && PROFILE_IsWideSpaceChar(szNameEnd[-1]))
		szNameEnd--;
	    Len = szNameEnd - szLineStart;
	    szValueStart++;
	    while (szValueStart < szLineEnd && PROFILE_IsWideSpaceChar(*szValueStart))
		szValueStart++;
	}

	if (Len || !PrevKey || *PrevKey->Name) {
	    /* no need to allocate +1 for NULL terminating character as
	     * already included in structure */
	    if (!(Key = HeapAlloc(GetProcessHeap(), 0,
				  sizeof(*Key) + Len * sizeof(WCHAR))))
		break;
	    memcpy(Key->Name, szLineStart, Len * sizeof(WCHAR));
	    Key->Name[Len] = '\0';
	    if (szValueStart) {
		Len = (int)(szLineEnd - szValueStart);
		Key->Value = HeapAlloc(GetProcessHeap(), 0, (Len + 1) * sizeof(WCHAR));
		memcpy(Key->Value, szValueStart, Len * sizeof(WCHAR));
		Key->Value[Len] = '\0';
	    } else
		Key->Value = NULL;

	    Key->Next = NULL;
	    *NextKey = Key;
	    NextKey = &Key->Next;
	    PrevKey = Key;

	    TRACE("New key: name=%s, value=%s\n", debugstr_w(key->name),
		  key->value ? debugstr_w(key->value) : L"(none)");
	}
    }
    if (szFile != pBuffer)
	HeapFree(GetProcessHeap(), 0, szFile);
    HeapFree(GetProcessHeap(), 0, BufferBase);
    return FirstSection;
}

/***********************************************************************
 *           PROFILE_DeleteSection
 *
 * Delete a section from a profile tree.
 */
static BOOL PROFILE_DeleteSection(PROFILESECTION **Section, LPCWSTR Name)
{
    while (*Section) {
	if (!strcmpiW((*Section)->Name, Name)) {
	    PROFILESECTION *ToDel = *Section;
	    *Section = ToDel->Next;
	    ToDel->Next = NULL;
	    PROFILE_Free(ToDel);
	    return TRUE;
	}
	Section = &(*Section)->Next;
    }
    return FALSE;
}

/***********************************************************************
 *           PROFILE_DeleteKey
 *
 * Delete a key from a profile tree.
 */
static BOOL PROFILE_DeleteKey(PROFILESECTION **Section, LPCWSTR SectionName,
			      LPCWSTR KeyName)
{
    while (*Section) {
	if (!strcmpiW((*Section)->Name, SectionName)) {
	    PROFILEKEY **Key = &(*Section)->Key;
	    while (*Key) {
		if (!strcmpiW((*Key)->Name, KeyName)) {
		    PROFILEKEY *ToDel = *Key;
		    *Key = ToDel->Next;
		    HeapFree(GetProcessHeap(), 0, ToDel->Value);
		    HeapFree(GetProcessHeap(), 0, ToDel);
		    return TRUE;
		}
		Key = &(*Key)->Next;
	    }
	}
	Section = &(*Section)->Next;
    }
    return FALSE;
}

/***********************************************************************
 *           PROFILE_DeleteAllKeys
 *
 * Delete all keys from a profile tree.
 */
static void PROFILE_DeleteAllKeys(LPCWSTR SectionName)
{
    PROFILESECTION **Section = &CURRENT_PROFILE->Section;
    while (*Section) {
	if (!strcmpiW((*Section)->Name, SectionName)) {
	    PROFILEKEY **Key = &(*Section)->Key;
	    while (*Key) {
		PROFILEKEY *ToDel = *Key;
		*Key = ToDel->Next;
		HeapFree(GetProcessHeap(), 0, ToDel->Value);
		HeapFree(GetProcessHeap(), 0, ToDel);
		CURRENT_PROFILE->Changed = TRUE;
	    }
	}
	Section = &(*Section)->Next;
    }
}

/***********************************************************************
 *           PROFILE_Find
 *
 * Find a key in a profile tree, optionally creating it.
 */
static PROFILEKEY *PROFILE_Find(PROFILESECTION **Section, LPCWSTR SectionName,
				LPCWSTR KeyName, BOOL Create, BOOL CreateAlways)
{
    LPCWSTR p;
    int Seclen = 0, Keylen = 0;

    while (PROFILE_IsWideSpaceChar(*SectionName))
	SectionName++;
    if (*SectionName) {
	p = SectionName + strlenW(SectionName) - 1;
	while ((p > SectionName) && PROFILE_IsWideSpaceChar(*p))
	    p--;
	Seclen = p - SectionName + 1;
    }

    while (PROFILE_IsWideSpaceChar(*KeyName))
	KeyName++;
    if (*KeyName) {
	p = KeyName + strlenW(KeyName) - 1;
	while ((p > KeyName) && PROFILE_IsWideSpaceChar(*p))
	    p--;
	Keylen = p - KeyName + 1;
    }

    while (*Section) {
	if (!strncmpiW((*Section)->Name, SectionName, Seclen) &&
	    ((*Section)->Name)[Seclen] == '\0') {
	    PROFILEKEY **Key = &(*Section)->Key;

	    while (*Key) {
		/* If create_always is FALSE then we check if the keyname
		 * already exists. Otherwise we add it regardless of its
		 * existence, to allow keys to be added more than once in
		 * some cases.
		 */
		if (!CreateAlways) {
		    if ((!(strncmpiW((*Key)->Name, KeyName, Keylen))) &&
			(((*Key)->Name)[Keylen] == '\0'))
			return *Key;
		}
		Key = &(*Key)->Next;
	    }
	    if (!Create)
		return NULL;
	    ULONG KeyNameLen = strlenW(KeyName);
	    if (!(*Key = HeapAlloc(GetProcessHeap(), 0,
				   sizeof(PROFILEKEY) +
				   KeyNameLen * sizeof(WCHAR))))
		return NULL;
	    wcscpy_s((*Key)->Name, KeyNameLen + 1, KeyName);
	    (*Key)->Value = NULL;
	    (*Key)->Next = NULL;
	    return *Key;
	}
	Section = &(*Section)->Next;
    }
    if (!Create)
	return NULL;
    ULONG SectionNameLen = strlenW(SectionName);
    *Section = HeapAlloc(GetProcessHeap(), 0,
			 sizeof(PROFILESECTION) + SectionNameLen * sizeof(WCHAR));
    if (*Section == NULL)
	return NULL;
    wcscpy_s((*Section)->Name, SectionNameLen + 1, SectionName);
    (*Section)->Next = NULL;
    ULONG KeyNameLen = strlenW(KeyName);
    if (!((*Section)->Key = HeapAlloc(GetProcessHeap(), 0,
				      sizeof(PROFILEKEY) +
				      KeyNameLen * sizeof(WCHAR)))) {
	HeapFree(GetProcessHeap(), 0, *Section);
	return NULL;
    }
    wcscpy_s((*Section)->Key->Name, KeyNameLen + 1, KeyName);
    (*Section)->Key->Value = NULL;
    (*Section)->Key->Next = NULL;
    return (*Section)->Key;
}

/***********************************************************************
 *           PROFILE_FlushFile
 *
 * Flush the current profile to disk if changed.
 */
static BOOL PROFILE_FlushFile(void)
{
    HANDLE hFile = NULL;
    FILETIME LastWriteTime;

    if (!CURRENT_PROFILE) {
	WARN("No current profile!\n");
	return FALSE;
    }

    if (!CURRENT_PROFILE->Changed)
	return TRUE;

    hFile = CreateFileW(CURRENT_PROFILE->Filename, GENERIC_WRITE,
			FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS,
			FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
	WARN("could not save profile file %s (error was %d)\n",
	     debugstr_w(CURRENT_PROFILE->filename), GetLastError());
	return FALSE;
    }

    TRACE("Saving %s\n", debugstr_w(CURRENT_PROFILE->filename));
    PROFILE_Save(hFile, CURRENT_PROFILE->Section, CURRENT_PROFILE->Encoding);
    if (GetFileTime(hFile, NULL, NULL, &LastWriteTime))
	CURRENT_PROFILE->LastWriteTime = LastWriteTime;
    CloseHandle(hFile);
    CURRENT_PROFILE->Changed = FALSE;
    return TRUE;
}

/***********************************************************************
 *           PROFILE_ReleaseFile
 *
 * Flush the current profile to disk and remove it from the cache.
 */
static void PROFILE_ReleaseFile(void)
{
    PROFILE_FlushFile();
    PROFILE_Free(CURRENT_PROFILE->Section);
    HeapFree(GetProcessHeap(), 0, CURRENT_PROFILE->Filename);
    CURRENT_PROFILE->Changed = FALSE;
    CURRENT_PROFILE->Section = NULL;
    CURRENT_PROFILE->Filename = NULL;
    CURRENT_PROFILE->Encoding = ENCODING_ANSI;
    ZeroMemory(&CURRENT_PROFILE->LastWriteTime, sizeof(CURRENT_PROFILE->LastWriteTime));
}

/***********************************************************************
 *
 * Compares a file time with the current time. If the file time is
 * at least 2.1 seconds in the past, return true.
 *
 * Intended as cache safety measure: The time resolution on FAT is
 * two seconds, so files that are not at least two seconds old might
 * keep their time even on modification, so don't cache them.
 */
static BOOL IsNotCurrent(FILETIME *Ft)
{
    FILETIME Now;
    LONGLONG Ftll, Nowll;
    GetSystemTimeAsFileTime(&Now);
    Ftll = ((LONGLONG)Ft->dwHighDateTime << 32) + Ft->dwLowDateTime;
    Nowll = ((LONGLONG)Now.dwHighDateTime << 32) + Now.dwLowDateTime;
    TRACE("%08x;%08x\n", (unsigned)ftll + 21000000, (unsigned)nowll);
    return Ftll + 21000000 < Nowll;
}

/***********************************************************************
 *           PROFILE_Open
 *
 * Open a profile file, checking the cached file first.
 */
static BOOL PROFILE_Open(LPCWSTR Filename, BOOL WriteAccess)
{
    WCHAR Buffer[MAX_PATH];
    HANDLE hFile = INVALID_HANDLE_VALUE;
    FILETIME LastWriteTime;
    int i, j;
    PROFILE *TempProfile;

    ZeroMemory(&LastWriteTime, sizeof(LastWriteTime));

    /* First time around */

    if (!CURRENT_PROFILE)
	for (i = 0; i < N_CACHED_PROFILES; i++) {
	    MRUProfile[i] = HeapAlloc(GetProcessHeap(), 0, sizeof(PROFILE));
	    if (MRUProfile[i] == NULL)
		break;
	    MRUProfile[i]->Changed = FALSE;
	    MRUProfile[i]->Section = NULL;
	    MRUProfile[i]->Filename = NULL;
	    MRUProfile[i]->Encoding = ENCODING_ANSI;
	    ZeroMemory(&MRUProfile[i]->LastWriteTime, sizeof(FILETIME));
	}

    if (!Filename)
	Filename = WininiW;

    if ((RtlDetermineDosPathNameType_U(Filename) == RtlPathTypeRelative) &&
	!strchrW(Filename, '\\') && !strchrW(Filename, '/')) {
	static const WCHAR WszSeparator[] = { '\\', 0 };
	WCHAR WindirW[MAX_PATH];
	GetWindowsDirectoryW(WindirW, MAX_PATH);
	wcscpy_s(Buffer, ARRAYSIZE(Buffer), WindirW);
	wcscat_s(Buffer, ARRAYSIZE(Buffer), WszSeparator);
	wcscat_s(Buffer, ARRAYSIZE(Buffer), Filename);
    } else {
	LPWSTR Dummy;
	GetFullPathNameW(Filename, sizeof(Buffer) / sizeof(Buffer[0]), Buffer, &Dummy);
    }

    TRACE("path: %s\n", debugstr_w(buffer));

    hFile = CreateFileW(Buffer, GENERIC_READ | (WriteAccess ? GENERIC_WRITE : 0),
			FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
			OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if ((hFile == INVALID_HANDLE_VALUE) && (GetLastError() != ERROR_FILE_NOT_FOUND)) {
	WARN("Error %d opening file %s\n", GetLastError(), debugstr_w(buffer));
	return FALSE;
    }

    for (i = 0; i < N_CACHED_PROFILES; i++) {
	if ((MRUProfile[i]->Filename && !strcmpiW(Buffer, MRUProfile[i]->Filename))) {
	    TRACE("MRU Filename: %s, new filename: %s\n",
		  debugstr_w(MRUProfile[i]->filename), debugstr_w(buffer));
	    if (i) {
		PROFILE_FlushFile();
		TempProfile = MRUProfile[i];
		for (j = i; j > 0; j--)
		    MRUProfile[j] = MRUProfile[j - 1];
		CURRENT_PROFILE = TempProfile;
	    }

	    if (hFile != INVALID_HANDLE_VALUE) {
		GetFileTime(hFile, NULL, NULL, &LastWriteTime);
		if (!memcmp(&CURRENT_PROFILE->LastWriteTime, &LastWriteTime,
			    sizeof(FILETIME)) &&
		    IsNotCurrent(&LastWriteTime))
		    TRACE("(%s): already opened (mru=%d)\n", debugstr_w(buffer), i);
		else {
		    TRACE("(%s): already opened, needs refreshing (mru=%d)\n",
			  debugstr_w(buffer), i);
		    PROFILE_Free(CURRENT_PROFILE->Section);
		    CURRENT_PROFILE->Section = PROFILE_Load(hFile, &CURRENT_PROFILE->Encoding);
		    CURRENT_PROFILE->LastWriteTime = LastWriteTime;
		}
		CloseHandle(hFile);
		return TRUE;
	    } else
		TRACE("(%s): already opened, not yet created (mru=%d)\n",
		      debugstr_w(buffer), i);
	}
    }

    /* Flush the old current profile */
    PROFILE_FlushFile();

    /* Make the oldest profile the current one only in order to get rid of it */
    if (i == N_CACHED_PROFILES) {
	TempProfile = MRUProfile[N_CACHED_PROFILES - 1];
	for (i = N_CACHED_PROFILES - 1; i > 0; i--)
	    MRUProfile[i] = MRUProfile[i - 1];
	CURRENT_PROFILE = TempProfile;
    }
    if (CURRENT_PROFILE->Filename)
	PROFILE_ReleaseFile();

    /* OK, now that CURRENT_PROFILE is definitely free we assign it our new file */
    ULONG FileNameLen = strlenW(Buffer) + 1;
    CURRENT_PROFILE->Filename = HeapAlloc(GetProcessHeap(), 0,
					  FileNameLen * sizeof(WCHAR));
    wcscpy_s(CURRENT_PROFILE->Filename, FileNameLen, Buffer);

    if (hFile != INVALID_HANDLE_VALUE) {
	CURRENT_PROFILE->Section = PROFILE_Load(hFile, &CURRENT_PROFILE->Encoding);
	GetFileTime(hFile, NULL, NULL, &CURRENT_PROFILE->LastWriteTime);
	CloseHandle(hFile);
    } else {
	/* Does not exist yet, we will create it in PROFILE_FlushFile */
	WARN("profile file %s not found\n", debugstr_w(buffer));
    }
    return TRUE;
}

/***********************************************************************
 *           PROFILE_GetSection
 *
 * Returns all keys of a section.
 * If return_values is TRUE, also include the corresponding values.
 */
static INT PROFILE_GetSection(PROFILESECTION *Section, LPCWSTR SectionName,
			      LPWSTR Buffer, DWORD Len, BOOL ReturnValues)
{
    PROFILEKEY *Key;

    if (!Buffer)
	return 0;

    TRACE("%s,%p,%u\n", debugstr_w(section_name), buffer, len);

    while (Section) {
	if (!strcmpiW(Section->Name, SectionName)) {
	    UINT Oldlen = Len;
	    for (Key = Section->Key; Key; Key = Key->Next) {
		if (Len <= 2)
		    break;
		if (!*Key->Name)
		    continue; /* Skip empty lines */
		if (IS_ENTRY_COMMENT(Key->Name))
		    continue; /* Skip comments */
		if (!ReturnValues && !Key->Value)
		    continue; /* Skip lines w.o. '=' */
		PROFILE_CopyEntry(Buffer, Key->Name, Len - 1, 0);
		Len -= strlenW(Buffer) + 1;
		Buffer += strlenW(Buffer) + 1;
		if (Len < 2)
		    break;
		if (ReturnValues && Key->Value) {
		    Buffer[-1] = '=';
		    PROFILE_CopyEntry(Buffer, Key->Value, Len - 1, 0);
		    Len -= strlenW(Buffer) + 1;
		    Buffer += strlenW(Buffer) + 1;
		}
	    }
	    *Buffer = '\0';
	    if (Len <= 1)
	    /*If either lpszSection or lpszKey is NULL and the supplied
	      destination buffer is too small to hold all the strings,
	      the last string is truncated and followed by two null characters.
	      In this case, the return value is equal to cchReturnBuffer
	      minus two. */
	    {
		Buffer[-1] = '\0';
		return Oldlen - 2;
	    }
	    return Oldlen - Len;
	}
	Section = Section->Next;
    }
    Buffer[0] = Buffer[1] = '\0';
    return 0;
}

/* See GetPrivateProfileSectionNamesA for documentation */
static INT PROFILE_GetSectionNames(LPWSTR Buffer, DWORD Len)
{
    LPWSTR Buf;
    UINT Buflen, Tmplen;
    PROFILESECTION *Section;

    TRACE("(%p, %d)\n", buffer, len);

    if (!Buffer || !Len)
	return 0;
    if (Len == 1) {
	*Buffer = '\0';
	return 0;
    }

    Buflen = Len - 1;
    Buf = Buffer;
    Section = CURRENT_PROFILE->Section;
    while ((Section != NULL)) {
	if (Section->Name[0]) {
	    Tmplen = strlenW(Section->Name) + 1;
	    if (Tmplen >= Buflen) {
		if (Buflen > 0) {
		    memcpy(Buf, Section->Name, (Buflen - 1) * sizeof(WCHAR));
		    Buf += Buflen - 1;
		    *Buf++ = '\0';
		}
		*Buf = '\0';
		return Len - 2;
	    }
	    memcpy(Buf, Section->Name, Tmplen * sizeof(WCHAR));
	    Buf += Tmplen;
	    Buflen -= Tmplen;
	}
	Section = Section->Next;
    }
    *Buf = '\0';
    return Buf - Buffer;
}

/***********************************************************************
 *           PROFILE_GetString
 *
 * Get a profile string.
 *
 * Tests with GetPrivateProfileString16, W95a,
 * with filled buffer ("****...") and section "set1" and key_name "1" valid:
 * section	key_name	def_val		res	buffer
 * "set1"	"1"		"x"		43	[data]
 * "set1"	"1   "		"x"		43	[data]		(!)
 * "set1"	"  1  "'	"x"		43	[data]		(!)
 * "set1"	""		"x"		1	"x"
 * "set1"	""		"x   "		1	"x"		(!)
 * "set1"	""		"  x   "	3	"  x"		(!)
 * "set1"	NULL		"x"		6	"1\02\03\0\0"
 * "set1"	""		"x"		1	"x"
 * NULL		"1"		"x"		0	""		(!)
 * ""		"1"		"x"		1	"x"
 * NULL		NULL		""		0	""
 *
 *
 */
static INT PROFILE_GetString(LPCWSTR Section, LPCWSTR KeyName,
			     LPCWSTR DefVal, LPWSTR Buffer, DWORD Len)
{
    PROFILEKEY *Key = NULL;
    static const WCHAR EmptyStrW[] = { 0 };

    if (!Buffer || !Len)
	return 0;

    if (!DefVal)
	DefVal = EmptyStrW;
    if (KeyName) {
	Key = PROFILE_Find(&CURRENT_PROFILE->Section, Section, KeyName, FALSE, FALSE);
	PROFILE_CopyEntry(Buffer, (Key && Key->Value) ? Key->Value : DefVal, Len, TRUE);
	TRACE("(%s,%s,%s): returning %s\n", debugstr_w(section), debugstr_w(key_name),
	      debugstr_w(def_val), debugstr_w(buffer));
	return strlenW(Buffer);
    }
    /* no "else" here ! */
    if (Section) {
	INT Ret = PROFILE_GetSection(CURRENT_PROFILE->Section, Section, Buffer, Len, FALSE);
	if (!Buffer[0]) /* no luck -> def_val */
	{
	    PROFILE_CopyEntry(Buffer, DefVal, Len, TRUE);
	    Ret = strlenW(Buffer);
	}
	return Ret;
    }
    Buffer[0] = '\0';
    return 0;
}

/***********************************************************************
 *           PROFILE_SetString
 *
 * Set a profile string.
 */
static BOOL PROFILE_SetString(LPCWSTR SectionName, LPCWSTR KeyName, LPCWSTR Value,
			      BOOL CreateAlways)
{
    if (!KeyName) /* Delete a whole section */
    {
	TRACE("(%s)\n", debugstr_w(section_name));
	CURRENT_PROFILE->Changed |= PROFILE_DeleteSection(&CURRENT_PROFILE->Section, SectionName);
	return TRUE; /* Even if PROFILE_DeleteSection() has failed,
			this is not an error on application's level.*/
    } else if (!Value) /* Delete a key */
    {
	TRACE("(%s,%s)\n", debugstr_w(section_name), debugstr_w(key_name));
	CURRENT_PROFILE->Changed |= PROFILE_DeleteKey(&CURRENT_PROFILE->Section, SectionName,
						 KeyName);
	return TRUE; /* same error handling as above */
    } else /* Set the key value */
    {
	PROFILEKEY *Key = PROFILE_Find(&CURRENT_PROFILE->Section, SectionName, KeyName, TRUE,
				       CreateAlways);
	TRACE("(%s,%s,%s):\n", debugstr_w(section_name), debugstr_w(key_name),
	      debugstr_w(value));
	if (!Key)
	    return FALSE;

	/* strip the leading spaces. We can safely strip \n\r and
	 * friends too, they should not happen here anyway. */
	while (PROFILE_IsWideSpaceChar(*Value))
	    Value++;

	if (Key->Value) {
	    if (!strcmpW(Key->Value, Value)) {
		TRACE("  no change needed\n");
		return TRUE; /* No change needed */
	    }
	    TRACE("  replacing %s\n", debugstr_w(key->value));
	    HeapFree(GetProcessHeap(), 0, Key->Value);
	} else
	    TRACE("  creating key\n");
	ULONG ValueLen = strlenW(Value) + 1;
	Key->Value = HeapAlloc(GetProcessHeap(), 0, ValueLen * sizeof(WCHAR));
	wcscpy_s(Key->Value, ValueLen, Value);
	CURRENT_PROFILE->Changed = TRUE;
    }
    return TRUE;
}

/********************* API functions **********************************/

/***********************************************************************
 *           GetProfileIntA   (KERNEL32.@)
 */
WINAPI UINT GetProfileIntA(LPCSTR Section, LPCSTR Entry, INT DefVal)
{
    return GetPrivateProfileIntA(Section, Entry, DefVal, "win.ini");
}

/***********************************************************************
 *           GetProfileIntW   (KERNEL32.@)
 */
WINAPI UINT GetProfileIntW(LPCWSTR Section, LPCWSTR Entry, INT DefVal)
{
    return GetPrivateProfileIntW(Section, Entry, DefVal, WininiW);
}

/***********************************************************************
 *           GetPrivateProfileStringW   (KERNEL32.@)
 */
WINAPI DWORD GetPrivateProfileStringW(LPCWSTR Section, LPCWSTR Entry, LPCWSTR DefVal,
				      LPWSTR Buffer, DWORD Len, LPCWSTR Filename)
{
    int Ret;
    LPWSTR DefvalTmp = NULL;

    TRACE("%s,%s,%s,%p,%u,%s\n", debugstr_w(section), debugstr_w(entry),
	  debugstr_w(def_val), buffer, len, debugstr_w(filename));

    /* strip any trailing ' ' of def_val. */
    if (DefVal) {
	LPCWSTR p = DefVal + strlenW(DefVal) - 1;

	while (p > DefVal && *p == ' ')
	    p--;

	if (p >= DefVal) {
	    int Vlen = (int)(p - DefVal) + 1;

	    DefvalTmp = HeapAlloc(GetProcessHeap(), 0, (Vlen + 1) * sizeof(WCHAR));
	    memcpy(DefvalTmp, DefVal, Vlen * sizeof(WCHAR));
	    DefvalTmp[Vlen] = '\0';
	    DefVal = DefvalTmp;
	}
    }

    RtlEnterCriticalSection(&ProfileCritSect);

    if (PROFILE_Open(Filename, FALSE)) {
	if (Section == NULL)
	    Ret = PROFILE_GetSectionNames(Buffer, Len);
	else
	    /* PROFILE_GetString can handle the 'entry == NULL' case */
	    Ret = PROFILE_GetString(Section, Entry, DefVal, Buffer, Len);
    } else if (Buffer && DefVal) {
	lstrcpynW(Buffer, DefVal, Len);
	Ret = strlenW(Buffer);
    } else
	Ret = 0;

    RtlLeaveCriticalSection(&ProfileCritSect);

    HeapFree(GetProcessHeap(), 0, DefvalTmp);

    TRACE("returning %s, %d\n", debugstr_w(buffer), ret);

    return Ret;
}

/***********************************************************************
 *           GetPrivateProfileStringA   (KERNEL32.@)
 */
WINAPI DWORD GetPrivateProfileStringA(LPCSTR Section, LPCSTR Entry, LPCSTR DefVal,
				      LPSTR Buffer, DWORD Len, LPCSTR Filename)
{
    UNICODE_STRING SectionW, EntryW, DefValW, FilenameW;
    LPWSTR BufferW;
    INT RetW, Ret = 0;

    BufferW = Buffer ? HeapAlloc(GetProcessHeap(), 0, Len * sizeof(WCHAR)) : NULL;
    if (Section)
	RtlCreateUnicodeStringFromAsciiz(&SectionW, Section);
    else
	SectionW.Buffer = NULL;
    if (Entry)
	RtlCreateUnicodeStringFromAsciiz(&EntryW, Entry);
    else
	EntryW.Buffer = NULL;
    if (DefVal)
	RtlCreateUnicodeStringFromAsciiz(&DefValW, DefVal);
    else
	DefValW.Buffer = NULL;
    if (Filename)
	RtlCreateUnicodeStringFromAsciiz(&FilenameW, Filename);
    else
	FilenameW.Buffer = NULL;

    RetW = GetPrivateProfileStringW(SectionW.Buffer, EntryW.Buffer, DefValW.Buffer,
				    BufferW, Len, FilenameW.Buffer);
    if (Len && Buffer) {
	if (RetW) {
	    Ret = WideCharToMultiByte(CP_ACP, 0, BufferW, RetW, Buffer, Len - 1, NULL,
				      NULL);
	    if (!Ret)
		Ret = Len - 1;
	}
	Buffer[Ret] = 0;
    }

    RtlFreeUnicodeString(&SectionW);
    RtlFreeUnicodeString(&EntryW);
    RtlFreeUnicodeString(&DefValW);
    RtlFreeUnicodeString(&FilenameW);
    HeapFree(GetProcessHeap(), 0, BufferW);
    return Ret;
}

/***********************************************************************
 *           GetProfileStringA   (KERNEL32.@)
 */
WINAPI DWORD GetProfileStringA(LPCSTR Section, LPCSTR Entry, LPCSTR DefVal, LPSTR Buffer,
			       DWORD Len)
{
    return GetPrivateProfileStringA(Section, Entry, DefVal, Buffer, Len, "win.ini");
}

/***********************************************************************
 *           GetProfileStringW   (KERNEL32.@)
 */
WINAPI DWORD GetProfileStringW(LPCWSTR Section, LPCWSTR Entry, LPCWSTR DefVal,
			       LPWSTR Buffer, DWORD Len)
{
    return GetPrivateProfileStringW(Section, Entry, DefVal, Buffer, Len, WininiW);
}

/***********************************************************************
 *           WriteProfileStringA   (KERNEL32.@)
 */
WINAPI BOOL WriteProfileStringA(LPCSTR Section, LPCSTR Entry, LPCSTR String)
{
    return WritePrivateProfileStringA(Section, Entry, String, "win.ini");
}

/***********************************************************************
 *           WriteProfileStringW   (KERNEL32.@)
 */
WINAPI BOOL WriteProfileStringW(LPCWSTR Section, LPCWSTR Entry, LPCWSTR String)
{
    return WritePrivateProfileStringW(Section, Entry, String, WininiW);
}

/***********************************************************************
 *           GetPrivateProfileIntW   (KERNEL32.@)
 */
WINAPI UINT GetPrivateProfileIntW(LPCWSTR Section, LPCWSTR Entry, INT DefVal,
				  LPCWSTR Filename)
{
    WCHAR Buffer[30];
    UNICODE_STRING BufferW;
    ULONG Result;

    if (GetPrivateProfileStringW(Section, Entry, EmptyStringW, Buffer,
				 sizeof(Buffer) / sizeof(WCHAR), Filename) == 0)
	return DefVal;

    /* FIXME: if entry can be found but it's empty, then Win16 is
     * supposed to return 0 instead of def_val ! Difficult/problematic
     * to implement (every other failure also returns zero buffer),
     * thus wait until testing framework avail for making sure nothing
     * else gets broken that way. */
    if (!Buffer[0])
	return (UINT)DefVal;

    RtlInitUnicodeString(&BufferW, Buffer);
    RtlUnicodeStringToInteger(&BufferW, 0, &Result);
    return Result;
}

/***********************************************************************
 *           GetPrivateProfileIntA   (KERNEL32.@)
 *
 * FIXME: rewrite using unicode
 */
WINAPI UINT GetPrivateProfileIntA(LPCSTR Section, LPCSTR Entry, INT DefVal,
				  LPCSTR Filename)
{
    UNICODE_STRING EntryW, FilenameW, SectionW;
    UINT Res;
    if (Entry)
	RtlCreateUnicodeStringFromAsciiz(&EntryW, Entry);
    else
	EntryW.Buffer = NULL;
    if (Filename)
	RtlCreateUnicodeStringFromAsciiz(&FilenameW, Filename);
    else
	FilenameW.Buffer = NULL;
    if (Section)
	RtlCreateUnicodeStringFromAsciiz(&SectionW, Section);
    else
	SectionW.Buffer = NULL;
    Res = GetPrivateProfileIntW(SectionW.Buffer, EntryW.Buffer, DefVal,
				FilenameW.Buffer);
    RtlFreeUnicodeString(&SectionW);
    RtlFreeUnicodeString(&FilenameW);
    RtlFreeUnicodeString(&EntryW);
    return Res;
}

/***********************************************************************
 *           GetPrivateProfileSectionW   (KERNEL32.@)
 */
WINAPI DWORD GetPrivateProfileSectionW(LPCWSTR Section, LPWSTR Buffer,
				       DWORD Len, LPCWSTR Filename)
{
    int Ret = 0;

    if (!Section || !Buffer) {
	SetLastError(ERROR_INVALID_PARAMETER);
	return 0;
    }

    TRACE("(%s, %p, %d, %s)\n", debugstr_w(section), buffer, len, debugstr_w(filename));

    RtlEnterCriticalSection(&ProfileCritSect);

    if (PROFILE_Open(Filename, FALSE))
	Ret = PROFILE_GetSection(CURRENT_PROFILE->Section, Section, Buffer, Len, TRUE);

    RtlLeaveCriticalSection(&ProfileCritSect);

    return Ret;
}

/***********************************************************************
 *           GetPrivateProfileSectionA   (KERNEL32.@)
 */
WINAPI DWORD GetPrivateProfileSectionA(LPCSTR Section, LPSTR Buffer,
				       DWORD Len, LPCSTR Filename)
{
    UNICODE_STRING SectionW, FilenameW;
    LPWSTR BufferW;
    INT RetW, Ret = 0;

    if (!Section || !Buffer) {
	SetLastError(ERROR_INVALID_PARAMETER);
	return 0;
    }

    BufferW = HeapAlloc(GetProcessHeap(), 0, Len * 2 * sizeof(WCHAR));
    RtlCreateUnicodeStringFromAsciiz(&SectionW, Section);
    if (Filename)
	RtlCreateUnicodeStringFromAsciiz(&FilenameW, Filename);
    else
	FilenameW.Buffer = NULL;

    RetW = GetPrivateProfileSectionW(SectionW.Buffer, BufferW, Len * 2, FilenameW.Buffer);
    if (RetW) {
	if (RetW == Len * 2 - 2)
	    RetW++; /* overflow */
	Ret = WideCharToMultiByte(CP_ACP, 0, BufferW, RetW + 1, Buffer, Len, NULL, NULL);
	if (!Ret || Ret == Len) /* overflow */
	{
	    Ret = Len - 2;
	    Buffer[Len - 2] = 0;
	    Buffer[Len - 1] = 0;
	} else
	    Ret--;
    } else {
	Buffer[0] = 0;
	Buffer[1] = 0;
    }

    RtlFreeUnicodeString(&SectionW);
    RtlFreeUnicodeString(&FilenameW);
    HeapFree(GetProcessHeap(), 0, BufferW);
    return Ret;
}

/***********************************************************************
 *           GetProfileSectionA   (KERNEL32.@)
 */
WINAPI DWORD GetProfileSectionA(LPCSTR Section, LPSTR Buffer, DWORD Len)
{
    return GetPrivateProfileSectionA(Section, Buffer, Len, "win.ini");
}

/***********************************************************************
 *           GetProfileSectionW   (KERNEL32.@)
 */
WINAPI DWORD GetProfileSectionW(LPCWSTR Section, LPWSTR Buffer, DWORD Len)
{
    return GetPrivateProfileSectionW(Section, Buffer, Len, WininiW);
}

/***********************************************************************
 *           WritePrivateProfileStringW   (KERNEL32.@)
 */
WINAPI BOOL WritePrivateProfileStringW(LPCWSTR Section, LPCWSTR Entry, LPCWSTR String,
				       LPCWSTR Filename)
{
    BOOL Ret = FALSE;

    RtlEnterCriticalSection(&ProfileCritSect);

    if (!Section && !Entry && !String) /* documented "file flush" case */
    {
	if (!Filename || PROFILE_Open(Filename, TRUE)) {
	    if (CURRENT_PROFILE)
		PROFILE_ReleaseFile(); /* always return FALSE in this case */
	}
    } else if (PROFILE_Open(Filename, TRUE)) {
	if (!Section) {
	    SetLastError(ERROR_FILE_NOT_FOUND);
	} else {
	    Ret = PROFILE_SetString(Section, Entry, String, FALSE);
	    if (Ret)
		Ret = PROFILE_FlushFile();
	}
    }

    RtlLeaveCriticalSection(&ProfileCritSect);
    return Ret;
}

/***********************************************************************
 *           WritePrivateProfileStringA   (KERNEL32.@)
 */
WINAPI DECLSPEC_HOTPATCH BOOL WritePrivateProfileStringA(LPCSTR Section, LPCSTR Entry,
							 LPCSTR String, LPCSTR Filename)
{
    UNICODE_STRING SectionW, EntryW, StringW, FilenameW;
    BOOL Ret;

    if (Section)
	RtlCreateUnicodeStringFromAsciiz(&SectionW, Section);
    else
	SectionW.Buffer = NULL;
    if (Entry)
	RtlCreateUnicodeStringFromAsciiz(&EntryW, Entry);
    else
	EntryW.Buffer = NULL;
    if (String)
	RtlCreateUnicodeStringFromAsciiz(&StringW, String);
    else
	StringW.Buffer = NULL;
    if (Filename)
	RtlCreateUnicodeStringFromAsciiz(&FilenameW, Filename);
    else
	FilenameW.Buffer = NULL;

    Ret = WritePrivateProfileStringW(SectionW.Buffer, EntryW.Buffer, StringW.Buffer,
				     FilenameW.Buffer);
    RtlFreeUnicodeString(&SectionW);
    RtlFreeUnicodeString(&EntryW);
    RtlFreeUnicodeString(&StringW);
    RtlFreeUnicodeString(&FilenameW);
    return Ret;
}

/***********************************************************************
 *           WritePrivateProfileSectionW   (KERNEL32.@)
 */
WINAPI BOOL WritePrivateProfileSectionW(LPCWSTR Section, LPCWSTR String, LPCWSTR Filename)
{
    BOOL Ret = FALSE;
    LPWSTR p;

    RtlEnterCriticalSection(&ProfileCritSect);

    if (!Section && !String) {
	if (!Filename || PROFILE_Open(Filename, TRUE)) {
	    if (CURRENT_PROFILE)
		PROFILE_ReleaseFile(); /* always return FALSE in this case */
	}
    } else if (PROFILE_Open(Filename, TRUE)) {
	if (!String) { /* delete the named section*/
	    Ret = PROFILE_SetString(Section, NULL, NULL, FALSE);
	} else {
	    PROFILE_DeleteAllKeys(Section);
	    Ret = TRUE;
	    while (*String && Ret) {
		ULONG StringLen = strlenW(String) + 1;
		LPWSTR Buf = HeapAlloc(GetProcessHeap(), 0,
				       StringLen * sizeof(WCHAR));
		wcscpy_s(Buf, StringLen, String);
		if ((p = strchrW(Buf, '='))) {
		    *p = '\0';
		    Ret = PROFILE_SetString(Section, Buf, p + 1, TRUE);
		}
		HeapFree(GetProcessHeap(), 0, Buf);
		String += strlenW(String) + 1;
	    }
	}
	if (Ret)
	    Ret = PROFILE_FlushFile();
    }

    RtlLeaveCriticalSection(&ProfileCritSect);
    return Ret;
}

/***********************************************************************
 *           WritePrivateProfileSectionA   (KERNEL32.@)
 */
WINAPI BOOL WritePrivateProfileSectionA(LPCSTR Section, LPCSTR String, LPCSTR Filename)

{
    UNICODE_STRING SectionW, FilenameW;
    LPWSTR StringW;
    BOOL Ret;

    if (String) {
	INT LenA, LenW;
	LPCSTR p = String;

	while (*p)
	    p += strlen(p) + 1;
	LenA = p - String + 1;
	LenW = MultiByteToWideChar(CP_ACP, 0, String, LenA, NULL, 0);
	if ((StringW = HeapAlloc(GetProcessHeap(), 0, LenW * sizeof(WCHAR))))
	    MultiByteToWideChar(CP_ACP, 0, String, LenA, StringW, LenW);
    } else
	StringW = NULL;
    if (Section)
	RtlCreateUnicodeStringFromAsciiz(&SectionW, Section);
    else
	SectionW.Buffer = NULL;
    if (Filename)
	RtlCreateUnicodeStringFromAsciiz(&FilenameW, Filename);
    else
	FilenameW.Buffer = NULL;

    Ret = WritePrivateProfileSectionW(SectionW.Buffer, StringW, FilenameW.Buffer);

    HeapFree(GetProcessHeap(), 0, StringW);
    RtlFreeUnicodeString(&SectionW);
    RtlFreeUnicodeString(&FilenameW);
    return Ret;
}

/***********************************************************************
 *           WriteProfileSectionA   (KERNEL32.@)
 */
WINAPI BOOL WriteProfileSectionA(LPCSTR Section, LPCSTR KeysNValues)

{
    return WritePrivateProfileSectionA(Section, KeysNValues, "win.ini");
}

/***********************************************************************
 *           WriteProfileSectionW   (KERNEL32.@)
 */
WINAPI BOOL WriteProfileSectionW(LPCWSTR Section, LPCWSTR KeysNValues)
{
    return WritePrivateProfileSectionW(Section, KeysNValues, WininiW);
}

/***********************************************************************
 *           GetPrivateProfileSectionNamesW  (KERNEL32.@)
 *
 * Returns the section names contained in the specified file.
 * FIXME: Where do we find this file when the path is relative?
 * The section names are returned as a list of strings with an extra
 * '\0' to mark the end of the list. Except for that the behavior
 * depends on the Windows version.
 *
 * Win95:
 * - if the buffer is 0 or 1 character long then it is as if it was of
 *   infinite length.
 * - otherwise, if the buffer is too small only the section names that fit
 *   are returned.
 * - note that this means if the buffer was too small to return even just
 *   the first section name then a single '\0' will be returned.
 * - the return value is the number of characters written in the buffer,
 *   except if the buffer was too small in which case len-2 is returned
 *
 * Win2000:
 * - if the buffer is 0, 1 or 2 characters long then it is filled with
 *   '\0' and the return value is 0
 * - otherwise if the buffer is too small then the first section name that
 *   does not fit is truncated so that the string list can be terminated
 *   correctly (double '\0')
 * - the return value is the number of characters written in the buffer
 *   except for the trailing '\0'. If the buffer is too small, then the
 *   return value is len-2
 * - Win2000 has a bug that triggers when the section names and the
 *   trailing '\0' fit exactly in the buffer. In that case the trailing
 *   '\0' is missing.
 *
 * Wine implements the observed Win2000 behavior (except for the bug).
 *
 * Note that when the buffer is big enough then the return value may be any
 * value between 1 and len-1 (or len in Win95), including len-2.
 */
WINAPI DWORD GetPrivateProfileSectionNamesW(LPWSTR Buffer, DWORD Size, LPCWSTR Filename)
{
    DWORD Ret = 0;

    RtlEnterCriticalSection(&ProfileCritSect);

    if (PROFILE_Open(Filename, FALSE))
	Ret = PROFILE_GetSectionNames(Buffer, Size);

    RtlLeaveCriticalSection(&ProfileCritSect);

    return Ret;
}

/***********************************************************************
 *           GetPrivateProfileSectionNamesA  (KERNEL32.@)
 */
WINAPI DWORD GetPrivateProfileSectionNamesA(LPSTR Buffer, DWORD Size, LPCSTR Filename)
{
    UNICODE_STRING FilenameW;
    LPWSTR BufferW;
    INT RetW, Ret = 0;

    BufferW = Buffer ? HeapAlloc(GetProcessHeap(), 0, Size * sizeof(WCHAR)) : NULL;
    if (Filename)
	RtlCreateUnicodeStringFromAsciiz(&FilenameW, Filename);
    else
	FilenameW.Buffer = NULL;

    RetW = GetPrivateProfileSectionNamesW(BufferW, Size, FilenameW.Buffer);
    if (RetW && Size) {
	Ret = WideCharToMultiByte(CP_ACP, 0, BufferW, RetW + 1, Buffer, Size - 1, NULL,
				  NULL);
	if (!Ret) {
	    Ret = Size - 2;
	    Buffer[Size - 1] = 0;
	} else
	    Ret = Ret - 1;
    } else if (Size)
	Buffer[0] = '\0';

    RtlFreeUnicodeString(&FilenameW);
    HeapFree(GetProcessHeap(), 0, BufferW);
    return Ret;
}

/***********************************************************************
 *           GetPrivateProfileStructW (KERNEL32.@)
 *
 * Should match Win95's behaviour pretty much
 */
WINAPI BOOL GetPrivateProfileStructW(LPCWSTR Section, LPCWSTR Key, LPVOID Buf, UINT Len,
				     LPCWSTR Filename)
{
    BOOL Ret = FALSE;

    RtlEnterCriticalSection(&ProfileCritSect);

    if (PROFILE_Open(Filename, FALSE)) {
	PROFILEKEY *k = PROFILE_Find(&CURRENT_PROFILE->Section, Section, Key, FALSE, FALSE);
	if (k) {
	    TRACE("value (at %p): %s\n", k->value, debugstr_w(k->value));
	    if (((strlenW(k->Value) - 2) / 2) == Len) {
		LPWSTR End, p;
		BOOL Valid = TRUE;
		WCHAR c;
		DWORD Chksum = 0;

		End = k->Value + strlenW(k->Value); /* -> '\0' */
		/* check for invalid chars in ASCII coded hex string */
		for (p = k->Value; p < End; p++) {
		    if (!isxdigitW(*p)) {
			WARN("invalid char '%x' in file %s->[%s]->%s !\n", *p,
			     debugstr_w(filename), debugstr_w(section), debugstr_w(key));
			Valid = FALSE;
			break;
		    }
		}
		if (Valid) {
		    BOOL Highnibble = TRUE;
		    BYTE b = 0, Val;
		    LPBYTE Binbuf = Buf;

		    End -= 2; /* don't include checksum in output data */
		    /* translate ASCII hex format into binary data */
		    for (p = k->Value; p < End; p++) {
			c = toupperW(*p);
			Val = (c > '9') ? (c - 'A' + 10) : (c - '0');

			if (Highnibble)
			    b = Val << 4;
			else {
			    b += Val;
			    *Binbuf++ = b; /* feed binary data into output */
			    Chksum += b; /* calculate checksum */
			}
			Highnibble ^= 1; /* toggle */
		    }
		    /* retrieve stored checksum value */
		    c = toupperW(*p++);
		    b = ((c > '9') ? (c - 'A' + 10) : (c - '0')) << 4;
		    c = toupperW(*p);
		    b += (c > '9') ? (c - 'A' + 10) : (c - '0');
		    if (b == (Chksum & 0xff)) /* checksums match ? */
			Ret = TRUE;
		}
	    }
	}
    }
    RtlLeaveCriticalSection(&ProfileCritSect);

    return Ret;
}

/***********************************************************************
 *           GetPrivateProfileStructA (KERNEL32.@)
 */
WINAPI BOOL GetPrivateProfileStructA(LPCSTR Section, LPCSTR Key, LPVOID Buffer, UINT Len,
				     LPCSTR Filename)
{
    UNICODE_STRING SectionW, KeyW, FilenameW;
    INT Ret;

    if (Section)
	RtlCreateUnicodeStringFromAsciiz(&SectionW, Section);
    else
	SectionW.Buffer = NULL;
    if (Key)
	RtlCreateUnicodeStringFromAsciiz(&KeyW, Key);
    else
	KeyW.Buffer = NULL;
    if (Filename)
	RtlCreateUnicodeStringFromAsciiz(&FilenameW, Filename);
    else
	FilenameW.Buffer = NULL;

    Ret = GetPrivateProfileStructW(SectionW.Buffer, KeyW.Buffer, Buffer, Len,
				   FilenameW.Buffer);
    /* Do not translate binary data. */

    RtlFreeUnicodeString(&SectionW);
    RtlFreeUnicodeString(&KeyW);
    RtlFreeUnicodeString(&FilenameW);
    return Ret;
}

/***********************************************************************
 *           WritePrivateProfileStructW (KERNEL32.@)
 */
WINAPI BOOL WritePrivateProfileStructW(LPCWSTR Section, LPCWSTR Key, LPVOID Buf,
				       UINT Bufsize, LPCWSTR Filename)
{
    BOOL Ret = FALSE;
    LPBYTE Binbuf;
    LPWSTR Outstring, p;
    DWORD Sum = 0;

    if (!Section && !Key && !Buf) /* flush the cache */
	return WritePrivateProfileStringW(NULL, NULL, NULL, Filename);

    /* allocate string buffer for hex chars + checksum hex char + '\0' */
    Outstring = HeapAlloc(GetProcessHeap(), 0, (Bufsize * 2 + 2 + 1) * sizeof(WCHAR));
    p = Outstring;
    for (Binbuf = (LPBYTE)Buf; Binbuf < (LPBYTE)Buf + Bufsize; Binbuf++) {
	*p++ = Hex[*Binbuf >> 4];
	*p++ = Hex[*Binbuf & 0xf];
	Sum += *Binbuf;
    }
    /* checksum is sum & 0xff */
    *p++ = Hex[(Sum & 0xf0) >> 4];
    *p++ = Hex[Sum & 0xf];
    *p++ = '\0';

    RtlEnterCriticalSection(&ProfileCritSect);

    if (PROFILE_Open(Filename, TRUE)) {
	Ret = PROFILE_SetString(Section, Key, Outstring, FALSE);
	if (Ret)
	    Ret = PROFILE_FlushFile();
    }

    RtlLeaveCriticalSection(&ProfileCritSect);

    HeapFree(GetProcessHeap(), 0, Outstring);

    return Ret;
}

/***********************************************************************
 *           WritePrivateProfileStructA (KERNEL32.@)
 */
WINAPI BOOL WritePrivateProfileStructA(LPCSTR Section, LPCSTR Key, LPVOID Buf,
				       UINT Bufsize, LPCSTR Filename)
{
    UNICODE_STRING SectionW, KeyW, FilenameW;
    INT Ret;

    if (Section)
	RtlCreateUnicodeStringFromAsciiz(&SectionW, Section);
    else
	SectionW.Buffer = NULL;
    if (Key)
	RtlCreateUnicodeStringFromAsciiz(&KeyW, Key);
    else
	KeyW.Buffer = NULL;
    if (Filename)
	RtlCreateUnicodeStringFromAsciiz(&FilenameW, Filename);
    else
	FilenameW.Buffer = NULL;

    /* Do not translate binary data. */
    Ret = WritePrivateProfileStructW(SectionW.Buffer, KeyW.Buffer, Buf, Bufsize,
				     FilenameW.Buffer);

    RtlFreeUnicodeString(&SectionW);
    RtlFreeUnicodeString(&KeyW);
    RtlFreeUnicodeString(&FilenameW);
    return Ret;
}

/***********************************************************************
 *           OpenProfileUserMapping   (KERNEL32.@)
 */
WINAPI BOOL OpenProfileUserMapping(void)
{
    FIXME("(), stub!\n");
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

/***********************************************************************
 *           CloseProfileUserMapping   (KERNEL32.@)
 */
WINAPI BOOL CloseProfileUserMapping(void)
{
    FIXME("(), stub!\n");
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}
