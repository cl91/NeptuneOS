/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS system libraries
 * FILE:            dll/win32/kernel32/client/file/fileutils.c
 * PURPOSE:         File utility function shared with kernel32_vista
 * PROGRAMMER:      Taken from wine
 */

/* INCLUDES *****************************************************************/

#include <k32.h>

/* FUNCTIONS ****************************************************************/

PWCHAR FilenameA2W(LPCSTR NameA, BOOL Alloc)
{
    ANSI_STRING Str;
    UNICODE_STRING StrW;
    PUNICODE_STRING PstrW;
    NTSTATUS Status;

    // ASSERT(NtCurrentTeb()->Win32.StaticUnicodeString.Buffer ==
    // NtCurrentTeb()->Win32.StaticUnicodeBuffer);
    ASSERT(NtCurrentTeb()->Win32.StaticUnicodeString.MaximumLength ==
	   sizeof(NtCurrentTeb()->Win32.StaticUnicodeBuffer));

    RtlInitAnsiString(&Str, NameA);
    PstrW = Alloc ? &StrW : &NtCurrentTeb()->Win32.StaticUnicodeString;

    if (AreFileApisANSI())
	Status = RtlAnsiStringToUnicodeString(PstrW, &Str, (BOOLEAN)Alloc);
    else
	Status = RtlOemStringToUnicodeString(PstrW, &Str, (BOOLEAN)Alloc);

    if (NT_SUCCESS(Status))
	return PstrW->Buffer;

    if (Status == STATUS_BUFFER_OVERFLOW)
	SetLastError(ERROR_FILENAME_EXCED_RANGE);
    else
	BaseSetLastNTError(Status);

    return NULL;
}

/*
  No copy/conversion is done if the dest. buffer is too small.

  Returns:
   Success: number of TCHARS copied into dest. buffer NOT including nullterm
   Fail: size of buffer in TCHARS required to hold the converted filename, including nullterm
*/
DWORD FilenameU2A_FitOrFail(LPSTR DestA,
			    INT DestLen, /* buffer size in TCHARS incl. nullchar */
			    PUNICODE_STRING SourceU)
{
    DWORD Ret;

    /* destLen should never exceed MAX_PATH */
    if (DestLen > MAX_PATH)
	DestLen = MAX_PATH;

    Ret = AreFileApisANSI() ? RtlUnicodeStringToAnsiSize(SourceU) :
			      RtlUnicodeStringToOemSize(SourceU);
    /* ret incl. nullchar */

    if (DestA && (INT)Ret <= DestLen) {
	ANSI_STRING Str;

	Str.Buffer = DestA;
	Str.MaximumLength = (USHORT)DestLen;

	if (AreFileApisANSI())
	    RtlUnicodeStringToAnsiString(&Str, SourceU, FALSE);
	else
	    RtlUnicodeStringToOemString(&Str, SourceU, FALSE);

	Ret = Str.Length; /* SUCCESS: length without terminating 0 */
    }

    return Ret;
}

/*
  No copy/conversion is done if the dest. buffer is too small.

  Returns:
   Success: number of TCHARS copied into dest. buffer NOT including nullterm
   Fail: size of buffer in TCHARS required to hold the converted filename, including nullterm
*/
DWORD FilenameW2A_FitOrFail(LPSTR DestA,
			    INT DestLen, /* buffer size in TCHARS incl. nullchar */
			    LPCWSTR SourceW,
			    INT SourceLen) /* buffer size in TCHARS incl. nullchar */
{
    UNICODE_STRING StrW;

    if (SourceLen < 0)
	SourceLen = wcslen(SourceW) + 1;

    StrW.Buffer = (PWCHAR)SourceW;
    StrW.MaximumLength = SourceLen * sizeof(WCHAR);
    StrW.Length = StrW.MaximumLength - sizeof(WCHAR);

    return FilenameU2A_FitOrFail(DestA, DestLen, &StrW);
}

/*
  Return: num. TCHARS copied into dest including nullterm
*/
DWORD FilenameA2W_N(LPWSTR Dest, INT Destlen, /* buffer size in TCHARS incl. nullchar */
		    LPCSTR Src, INT Srclen) /* buffer size in TCHARS incl. nullchar */
{
    DWORD Ret;

    if (Srclen < 0)
	Srclen = strlen(Src) + 1;

    if (AreFileApisANSI())
	RtlMultiByteToUnicodeN(Dest, Destlen * sizeof(WCHAR), &Ret, (LPSTR)Src, Srclen);
    else
	RtlOemToUnicodeN(Dest, Destlen * sizeof(WCHAR), &Ret, (LPSTR)Src, Srclen);

    if (Ret)
	Dest[(Ret / sizeof(WCHAR)) - 1] = 0;

    return Ret / sizeof(WCHAR);
}

/*
  Return: num. TCHARS copied into dest including nullterm
*/
DWORD FilenameW2A_N(LPSTR Dest, INT Destlen, /* buffer size in TCHARS incl. nullchar */
		    LPCWSTR Src, INT Srclen) /* buffer size in TCHARS incl. nullchar */
{
    DWORD Ret;

    if (Srclen < 0)
	Srclen = wcslen(Src) + 1;

    if (AreFileApisANSI())
	RtlUnicodeToMultiByteN(Dest, Destlen, &Ret, (LPWSTR)Src, Srclen * sizeof(WCHAR));
    else
	RtlUnicodeToOemN(Dest, Destlen, &Ret, (LPWSTR)Src, Srclen * sizeof(WCHAR));

    if (Ret)
	Dest[Ret - 1] = 0;

    return Ret;
}

/* EOF */
