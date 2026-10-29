/*
 * FormatMessage implementation
 *
 * Copyright 1996 Marcus Meissner
 * Copyright 2009 Alexandre Julliard
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

DEBUG_CHANNEL(resource);

extern HMODULE Kernel32Handle;

struct FORMAT_ARGS {
    ULONG_PTR *Args;
    __ms_va_list *List;
    int Last;
};

/* Messages used by FormatMessage
 *
 * They can be specified either directly or using a message ID and
 * loading them from the resource.
 *
 * The resourcedata has following format:
 * start:
 * 0: DWORD nrofentries
 * nrofentries * subentry:
 *	0: DWORD firstentry
 *	4: DWORD lastentry
 *      8: DWORD offset from start to the stringentries
 *
 * (lastentry-firstentry) * stringentry:
 * 0: WORD len (0 marks end)	[ includes the 4 byte header length ]
 * 2: WORD flags
 * 4: CHAR[len-4]
 * 	(stringentry i of a subentry refers to the ID 'firstentry+i')
 *
 * Yes, ANSI strings in win32 resources. Go figure.
 */

/**********************************************************************
 *	LoadMessage    (internal)
 */
static LPWSTR LoadMessage(HMODULE Module, UINT Id, WORD Lang)
{
    MESSAGE_RESOURCE_ENTRY *Mre;
    WCHAR *Buffer;
    NTSTATUS Status;

    TRACE("module = %p, id = %08x\n", Module, Id);

    if (!Module)
	Module = GetModuleHandleW(NULL);
    Status = RtlFindMessage(Module, (ULONG_PTR)RT_MESSAGETABLE, Lang, Id, &Mre);
    if (!NT_SUCCESS(Status))
    {
	SetLastError(RtlNtStatusToDosError(Status));
	return NULL;
    }

    if (Mre->Flags & MESSAGE_RESOURCE_UNICODE) {
	int Len = (strlenW((const WCHAR *)Mre->Text) + 1) * sizeof(WCHAR);
	if (!(Buffer = HeapAlloc(GetProcessHeap(), 0, Len)))
	    return NULL;
	memcpy(Buffer, Mre->Text, Len);
    } else {
	int Len = MultiByteToWideChar(CP_ACP, 0, (const char *)Mre->Text, -1, NULL, 0);
	if (!(Buffer = HeapAlloc(GetProcessHeap(), 0, Len * sizeof(WCHAR))))
	    return NULL;
	MultiByteToWideChar(CP_ACP, 0, (const char *)Mre->Text, -1, Buffer, Len);
    }
    TRACE("returning %ws\n", Buffer);
    return Buffer;
}

static LPWSTR SearchMessage(DWORD Flags, HMODULE Module, UINT Id, WORD Lang)
{
    LPWSTR From = NULL;
    if (Flags & FORMAT_MESSAGE_FROM_HMODULE)
	From = LoadMessage(Module, Id, Lang);
    if (!From && (Flags & FORMAT_MESSAGE_FROM_SYSTEM)) {
	/* Fold win32 hresult to its embedded error code. */
	if (HRESULT_SEVERITY(Id) == SEVERITY_ERROR &&
	    HRESULT_FACILITY(Id) == FACILITY_WIN32) {
	    Id = HRESULT_CODE(Id);
	}
	From = LoadMessage(Kernel32Handle, Id, Lang);
    }
    return From;
}

/**********************************************************************
 *	GetArg    (internal)
 */
static ULONG_PTR GetArg(int Nr, DWORD Flags, struct FORMAT_ARGS *Args)
{
    if (Nr == -1)
	Nr = Args->Last + 1;
    if (Args->List) {
	if (!Args->Args)
	    Args->Args = HeapAlloc(GetProcessHeap(), 0, 99 * sizeof(ULONG_PTR));
	while (Nr > Args->Last)
	    Args->Args[Args->Last++] = va_arg(*Args->List, ULONG_PTR);
    }
    if (Nr > Args->Last)
	Args->Last = Nr;
    return Args->Args[Nr - 1];
}

/**********************************************************************
 *	FormatInsert    (internal)
 */
static LPCWSTR FormatInsert(BOOL UnicodeCaller, int Insert, LPCWSTR Format, DWORD Flags,
			    struct FORMAT_ARGS *Args, LPWSTR *Result)
{
    static const WCHAR FmtU[] = { '%', 'u', 0 };
    WCHAR *Wstring = NULL, *p, Fmt[256];
    ULONG_PTR Arg;
    int Size;

    if (*Format != '!') /* simple string */
    {
	Arg = GetArg(Insert, Flags, Args);
	if (UnicodeCaller || !Arg) {
	    static const WCHAR NullW[] = { '(', 'n', 'u', 'l', 'l', ')', 0 };
	    const WCHAR *Str = (const WCHAR *)Arg;

	    if (!Str)
		Str = NullW;
	    ULONG nChars = strlenW(Str) + 1;
	    *Result = HeapAlloc(GetProcessHeap(), 0, nChars * sizeof(WCHAR));
	    wcscpy_s(*Result, nChars, Str);
	} else {
	    const char *Str = (const char *)Arg;
	    DWORD Length = MultiByteToWideChar(CP_ACP, 0, Str, -1, NULL, 0);
	    *Result = HeapAlloc(GetProcessHeap(), 0, Length * sizeof(WCHAR));
	    MultiByteToWideChar(CP_ACP, 0, Str, -1, *Result, Length);
	}
	return Format;
    }

    Format++;
    p = Fmt;
    *p++ = '%';

    while (*Format == '0' || *Format == '+' || *Format == '-' || *Format == ' ' ||
	   *Format == '*' || *Format == '#') {
	if (*Format == '*') {
	    p += sprintfW(p, FmtU, GetArg(Insert, Flags, Args));
	    Insert = -1;
	    Format++;
	} else
	    *p++ = *Format++;
    }
    while (isdigitW(*Format))
	*p++ = *Format++;

    if (*Format == '.') {
	*p++ = *Format++;
	if (*Format == '*') {
	    p += sprintfW(p, FmtU, GetArg(Insert, Flags, Args));
	    Insert = -1;
	    Format++;
	} else
	    while (isdigitW(*Format))
		*p++ = *Format++;
    }

    /* replicate MS bug: drop an argument when using va_list with width/precision */
    if (Insert == -1 && Args->List)
	Args->Last--;
    Arg = GetArg(Insert, Flags, Args);

    /* check for ascii string format */
    if ((Format[0] == 'h' && Format[1] == 's') ||
	(Format[0] == 'h' && Format[1] == 'S') || (UnicodeCaller && Format[0] == 'S') ||
	(!UnicodeCaller && Format[0] == 's')) {
	DWORD Len = MultiByteToWideChar(CP_ACP, 0, (char *)Arg, -1, NULL, 0);
	Wstring = HeapAlloc(GetProcessHeap(), 0, Len * sizeof(WCHAR));
	MultiByteToWideChar(CP_ACP, 0, (char *)Arg, -1, Wstring, Len);
	Arg = (ULONG_PTR)Wstring;
	*p++ = 's';
    }
    /* check for ascii character format */
    else if ((Format[0] == 'h' && Format[1] == 'c') ||
	     (Format[0] == 'h' && Format[1] == 'C') ||
	     (UnicodeCaller && Format[0] == 'C') ||
	     (!UnicodeCaller && Format[0] == 'c')) {
	char Ch = Arg;
	Wstring = HeapAlloc(GetProcessHeap(), 0, 2 * sizeof(WCHAR));
	MultiByteToWideChar(CP_ACP, 0, &Ch, 1, Wstring, 1);
	Wstring[1] = 0;
	Arg = (ULONG_PTR)Wstring;
	*p++ = 's';
    }
    /* check for wide string format */
    else if ((Format[0] == 'l' && Format[1] == 's') ||
	     (Format[0] == 'l' && Format[1] == 'S') ||
	     (Format[0] == 'w' && Format[1] == 's') ||
	     (!UnicodeCaller && Format[0] == 'S')) {
	*p++ = 's';
    }
    /* check for wide character format */
    else if ((Format[0] == 'l' && Format[1] == 'c') ||
	     (Format[0] == 'l' && Format[1] == 'C') ||
	     (Format[0] == 'w' && Format[1] == 'c') ||
	     (!UnicodeCaller && Format[0] == 'C')) {
	*p++ = 'c';
    }
    /* FIXME: handle I64 etc. */
    else
	while (*Format && *Format != '!')
	    *p++ = *Format++;

    *p = 0;
    Size = 256;
    for (;;) {
	WCHAR *Ret = HeapAlloc(GetProcessHeap(), 0, Size * sizeof(WCHAR));
	int Needed = snprintfW(Ret, Size, Fmt, Arg);
	if (Needed == -1 || Needed >= Size) {
	    HeapFree(GetProcessHeap(), 0, Ret);
	    Size = max(Needed + 1, Size * 2);
	} else {
	    *Result = Ret;
	    break;
	}
    }

    while (*Format && *Format != '!')
	Format++;
    if (*Format == '!')
	Format++;

    HeapFree(GetProcessHeap(), 0, Wstring);
    return Format;
}

struct FORMAT_MESSAGE_DATA {
    LPWSTR Formatted;
    DWORD Size;
    LPWSTR t;
    LPWSTR Space;
    BOOL Inspace;
    DWORD Width, w;
};

static void FormatAddChar(struct FORMAT_MESSAGE_DATA *Fmd, WCHAR c)
{
    *Fmd->t++ = c;
    if (Fmd->Width && Fmd->Width != FORMAT_MESSAGE_MAX_WIDTH_MASK) {
	switch (c) {
	case '\r':
	case '\n':
	    Fmd->Space = NULL;
	    Fmd->Inspace = FALSE;
	    Fmd->w = 0;
	    break;
	case ' ':
	    if (!Fmd->Inspace)
		Fmd->Space = Fmd->t - 1;
	    Fmd->Inspace = TRUE;
	    Fmd->w++;
	    break;
	default:
	    Fmd->Inspace = FALSE;
	    Fmd->w++;
	}
	if (Fmd->w == Fmd->Width) {
	    LPWSTR Notspace;
	    if (Fmd->Space) {
		Notspace = Fmd->Space;
		while (Notspace != Fmd->t && *Notspace == ' ')
		    Notspace++;
	    } else
		Notspace = Fmd->Space = Fmd->t;
	    Fmd->w = Fmd->t - Notspace;
	    memmove(Fmd->Space + 2, Notspace, Fmd->w * sizeof(*Fmd->t));
	    *Fmd->Space++ = '\r';
	    *Fmd->Space++ = '\n';
	    Fmd->t = Fmd->Space + Fmd->w;
	    Fmd->Space = NULL;
	    Fmd->Inspace = FALSE;
	}
    }
    if ((DWORD)(Fmd->t - Fmd->Formatted) == Fmd->Size) {
	DWORD_PTR Ispace = Fmd->Space - Fmd->Formatted;
	/* Allocate two extra characters so we can insert a '\r\n' in
	 * the middle of a word.
	 */
	Fmd->Formatted = HeapReAlloc(GetProcessHeap(), 0, Fmd->Formatted,
				     (Fmd->Size * 2 + 2) * sizeof(WCHAR));
	Fmd->t = Fmd->Formatted + Fmd->Size;
	if (Fmd->Space)
	    Fmd->Space = Fmd->Formatted + Ispace;
	Fmd->Size *= 2;
    }
}

/**********************************************************************
 *	FormatMessage    (internal)
 */
static LPWSTR FormatMessageInternal(BOOL UnicodeCaller, DWORD dwFlags, LPCWSTR Fmtstr,
				    struct FORMAT_ARGS *FormatArgs)
{
    struct FORMAT_MESSAGE_DATA Fmd;
    LPCWSTR f;
    BOOL Eos = FALSE;

    Fmd.Size = 100;
    Fmd.Formatted = Fmd.t = HeapAlloc(GetProcessHeap(), 0,
				      (Fmd.Size + 2) * sizeof(WCHAR));

    Fmd.Width = dwFlags & FORMAT_MESSAGE_MAX_WIDTH_MASK;
    Fmd.w = 0;
    Fmd.Inspace = FALSE;
    Fmd.Space = NULL;
    f = Fmtstr;
    while (*f && !Eos) {
	if (*f == '%') {
	    int Insertnr;
	    WCHAR *Str, *x;

	    f++;
	    switch (*f) {
	    case '1':
	    case '2':
	    case '3':
	    case '4':
	    case '5':
	    case '6':
	    case '7':
	    case '8':
	    case '9':
		if (dwFlags & FORMAT_MESSAGE_IGNORE_INSERTS)
		    goto ignore_inserts;
		else if (((dwFlags & FORMAT_MESSAGE_ARGUMENT_ARRAY) &&
			  !FormatArgs->Args) ||
			 (!(dwFlags & FORMAT_MESSAGE_ARGUMENT_ARRAY) &&
			  !FormatArgs->List)) {
		    SetLastError(ERROR_INVALID_PARAMETER);
		    HeapFree(GetProcessHeap(), 0, Fmd.Formatted);
		    return NULL;
		}
		Insertnr = *f - '0';
		switch (f[1]) {
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
		    f++;
		    Insertnr = Insertnr * 10 + *f - '0';
		    f++;
		    break;
		default:
		    f++;
		    break;
		}
		f = FormatInsert(UnicodeCaller, Insertnr, f, dwFlags, FormatArgs,
				  &Str);
		for (x = Str; *x; x++)
		    FormatAddChar(&Fmd, *x);
		HeapFree(GetProcessHeap(), 0, Str);
		break;
	    case 'n':
		FormatAddChar(&Fmd, '\r');
		FormatAddChar(&Fmd, '\n');
		f++;
		break;
	    case 'r':
		FormatAddChar(&Fmd, '\r');
		f++;
		break;
	    case 't':
		FormatAddChar(&Fmd, '\t');
		f++;
		break;
	    case '0':
		Eos = TRUE;
		f++;
		break;
	    case '\0':
		SetLastError(ERROR_INVALID_PARAMETER);
		HeapFree(GetProcessHeap(), 0, Fmd.Formatted);
		return NULL;
	    ignore_inserts:
	    default:
		if (dwFlags & FORMAT_MESSAGE_IGNORE_INSERTS)
		    FormatAddChar(&Fmd, '%');
		FormatAddChar(&Fmd, *f++);
		break;
	    }
	} else {
	    WCHAR Ch = *f;
	    f++;
	    if (Ch == '\r') {
		if (*f == '\n')
		    f++;
		if (Fmd.Width)
		    FormatAddChar(&Fmd, ' ');
		else {
		    FormatAddChar(&Fmd, '\r');
		    FormatAddChar(&Fmd, '\n');
		}
	    } else {
		if (Ch == '\n') {
		    if (Fmd.Width)
			FormatAddChar(&Fmd, ' ');
		    else {
			FormatAddChar(&Fmd, '\r');
			FormatAddChar(&Fmd, '\n');
		    }
		} else
		    FormatAddChar(&Fmd, Ch);
	    }
	}
    }
    *Fmd.t = '\0';

    return Fmd.Formatted;
}

/***********************************************************************
 *           FormatMessageA   (KERNEL32.@)
 */
WINAPI DWORD FormatMessageA(DWORD dwFlags, LPCVOID lpSource, DWORD dwMessageId,
			    DWORD dwLanguageId, LPSTR lpBuffer, DWORD nSize,
			    __ms_va_list *Args)
{
    struct FORMAT_ARGS FormatArgs;
    DWORD Ret = 0;
    LPWSTR Target;
    DWORD Destlength;
    LPWSTR From;

    TRACE("(0x%x,%p,%d,0x%x,%p,%d,%p)\n", dwFlags, lpSource, dwMessageId, dwLanguageId,
	  lpBuffer, nSize, Args);

    if (dwFlags & FORMAT_MESSAGE_ALLOCATE_BUFFER) {
	if (!lpBuffer) {
	    SetLastError(ERROR_NOT_ENOUGH_MEMORY);
	    return 0;
	} else
	    *(LPSTR *)lpBuffer = NULL;
    }

    if (dwFlags & FORMAT_MESSAGE_ARGUMENT_ARRAY) {
	FormatArgs.Args = (ULONG_PTR *)Args;
	FormatArgs.List = NULL;
	FormatArgs.Last = 0;
    } else {
	FormatArgs.Args = NULL;
	FormatArgs.List = Args;
	FormatArgs.Last = 0;
    }

    From = NULL;
    if (dwFlags & FORMAT_MESSAGE_FROM_STRING) {
	DWORD Length = MultiByteToWideChar(CP_ACP, 0, lpSource, -1, NULL, 0);
	From = HeapAlloc(GetProcessHeap(), 0, Length * sizeof(WCHAR));
	MultiByteToWideChar(CP_ACP, 0, lpSource, -1, From, Length);
    } else if (dwFlags & (FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_FROM_SYSTEM)) {
	From = SearchMessage(dwFlags, (HMODULE)lpSource, dwMessageId, dwLanguageId);
	if (!From)
	    return 0;
    } else {
	SetLastError(ERROR_INVALID_PARAMETER);
	return 0;
    }

    Target = FormatMessageInternal(FALSE, dwFlags, From, &FormatArgs);
    if (!Target)
	goto failure;

    TRACE("-- %ws\n", Target);

    /* Only try writing to an output buffer if there are processed characters
     * in the temporary output buffer. */
    if (*Target) {
	Destlength = WideCharToMultiByte(CP_ACP, 0, Target, -1, NULL, 0, NULL, NULL);
	if (dwFlags & FORMAT_MESSAGE_ALLOCATE_BUFFER) {
	    LPSTR Buf = LocalAlloc(LMEM_ZEROINIT, max(nSize, Destlength));
	    WideCharToMultiByte(CP_ACP, 0, Target, -1, Buf, Destlength, NULL, NULL);
	    *((LPSTR *)lpBuffer) = Buf;
	} else {
	    if (nSize < Destlength) {
		SetLastError(ERROR_INSUFFICIENT_BUFFER);
		goto failure;
	    }
	    WideCharToMultiByte(CP_ACP, 0, Target, -1, lpBuffer, Destlength, NULL, NULL);
	}
	Ret = Destlength - 1; /* null terminator */
    }

failure:
    HeapFree(GetProcessHeap(), 0, Target);
    HeapFree(GetProcessHeap(), 0, From);
    if (!(dwFlags & FORMAT_MESSAGE_ARGUMENT_ARRAY))
	HeapFree(GetProcessHeap(), 0, FormatArgs.Args);
    TRACE("-- returning %u\n", Ret);
    return Ret;
}

/***********************************************************************
 *           FormatMessageW   (KERNEL32.@)
 */
WINAPI DWORD FormatMessageW(DWORD dwFlags, LPCVOID lpSource, DWORD dwMessageId,
			    DWORD dwLanguageId, LPWSTR lpBuffer, DWORD nSize,
			    __ms_va_list *Args)
{
    struct FORMAT_ARGS FormatArgs;
    DWORD Ret = 0;
    LPWSTR Target;
    DWORD Talloced;
    LPWSTR From;

    TRACE("(0x%x,%p,%d,0x%x,%p,%d,%p)\n", dwFlags, lpSource, dwMessageId, dwLanguageId,
	  lpBuffer, nSize, Args);

    if (!lpBuffer) {
	SetLastError(ERROR_INVALID_PARAMETER);
	return 0;
    }

    if (dwFlags & FORMAT_MESSAGE_ALLOCATE_BUFFER)
	*(LPWSTR *)lpBuffer = NULL;

    if (dwFlags & FORMAT_MESSAGE_ARGUMENT_ARRAY) {
	FormatArgs.Args = (ULONG_PTR *)Args;
	FormatArgs.List = NULL;
	FormatArgs.Last = 0;
    } else {
	FormatArgs.Args = NULL;
	FormatArgs.List = Args;
	FormatArgs.Last = 0;
    }

    From = NULL;
    if (dwFlags & FORMAT_MESSAGE_FROM_STRING) {
	ULONG nChars = strlenW(lpSource) + 1;
	From = HeapAlloc(GetProcessHeap(), 0, nChars * sizeof(WCHAR));
	wcscpy_s(From, nChars, lpSource);
    } else if (dwFlags & (FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_FROM_SYSTEM)) {
	From = SearchMessage(dwFlags, (HMODULE)lpSource, dwMessageId, dwLanguageId);
	if (!From)
	    return 0;
    } else {
	SetLastError(ERROR_INVALID_PARAMETER);
	return 0;
    }

    Target = FormatMessageInternal(TRUE, dwFlags, From, &FormatArgs);
    if (!Target)
	goto failure;

    Talloced = strlenW(Target) + 1;
    TRACE("-- %ws\n", Target);

    /* Only allocate a buffer if there are processed characters in the
     * temporary output buffer. If a caller supplies the buffer, then
     * a null terminator will be written to it. */
    if (dwFlags & FORMAT_MESSAGE_ALLOCATE_BUFFER) {
	if (*Target) {
	    /* nSize is the MINIMUM size */
	    *((LPVOID *)lpBuffer) = LocalAlloc(LMEM_ZEROINIT,
					       max(nSize, Talloced) * sizeof(WCHAR));
	    wcscpy_s(*(LPWSTR *)lpBuffer, max(nSize, Talloced), Target);
	}
    } else {
	if (nSize < Talloced) {
	    SetLastError(ERROR_INSUFFICIENT_BUFFER);
	    goto failure;
	}
	wcscpy_s(lpBuffer, nSize, Target);
    }

    Ret = Talloced - 1; /* null terminator */
failure:
    HeapFree(GetProcessHeap(), 0, Target);
    HeapFree(GetProcessHeap(), 0, From);
    if (!(dwFlags & FORMAT_MESSAGE_ARGUMENT_ARRAY))
	HeapFree(GetProcessHeap(), 0, FormatArgs.Args);
    TRACE("-- returning %u\n", Ret);
    return Ret;
}
