/*
 * PROJECT:         ReactOS Win32 Base API
 * LICENSE:         GPL - See COPYING in the top level directory
 * FILE:            dll/win32/kernel32/client/vdm.c
 * PURPOSE:         Virtual DOS Machines (VDM) Support
 * PROGRAMMERS:     Alex Ionescu (alex.ionescu@reactos.org)
 */

/* INCLUDES *******************************************************************/

#include <k32.h>

/* TYPES **********************************************************************/

#define BINARY_UNKNOWN (0)
#define BINARY_PE_EXE32 (1)
#define BINARY_PE_DLL32 (2)
#define BINARY_PE_EXE64 (3)
#define BINARY_PE_DLL64 (4)
#define BINARY_WIN16 (5)
#define BINARY_OS216 (6)
#define BINARY_DOS (7)
#define BINARY_UNIX_EXE (8)
#define BINARY_UNIX_LIB (9)

/* GLOBALS ********************************************************************/

static UNICODE_STRING BaseDotComSuffixName = RTL_CONSTANT_STRING(L".com");
static UNICODE_STRING BaseDotPifSuffixName = RTL_CONSTANT_STRING(L".pif");
static UNICODE_STRING BaseDotExeSuffixName = RTL_CONSTANT_STRING(L".exe");

/* FUNCTIONS ******************************************************************/

WINAPI ULONG BaseIsDosApplication(IN PUNICODE_STRING PathName, IN NTSTATUS Status)
{
    UNICODE_STRING String;

    /* Is it a .com? */
    String.Length = BaseDotComSuffixName.Length;
    String.Buffer = &PathName->Buffer[(PathName->Length - String.Length) / sizeof(WCHAR)];
    if (RtlEqualUnicodeString(&String, &BaseDotComSuffixName, TRUE))
	return BINARY_TYPE_COM;

    /* Is it a .pif? */
    String.Length = BaseDotPifSuffixName.Length;
    String.Buffer = &PathName->Buffer[(PathName->Length - String.Length) / sizeof(WCHAR)];
    if (RtlEqualUnicodeString(&String, &BaseDotPifSuffixName, TRUE))
	return BINARY_TYPE_PIF;

    /* Is it an exe? */
    String.Length = BaseDotExeSuffixName.Length;
    String.Buffer = &PathName->Buffer[(PathName->Length - String.Length) / sizeof(WCHAR)];
    if (RtlEqualUnicodeString(&String, &BaseDotExeSuffixName, TRUE))
	return BINARY_TYPE_EXE;

    return 0;
}

/* Check whether a file is an OS/2 or a very old Windows executable
 * by testing on import of KERNEL.
 *
 * FIXME: is reading the module imports the only way of discerning
 *        old Windows binaries from OS/2 ones ? At least it seems so...
 */
static WINAPI DWORD InternalIsOS2OrOldWin(HANDLE hFile, IMAGE_DOS_HEADER *MZ,
					  IMAGE_OS2_HEADER *NE)
{
    DWORD CurPos;
    LPWORD ModTab = NULL;
    LPSTR NameTab = NULL;
    DWORD Read, Ret;
    int i;

    Ret = BINARY_OS216;
    CurPos = SetFilePointer(hFile, 0, NULL, FILE_CURRENT);

    /* read modref table */
    if ((SetFilePointer(hFile, MZ->e_lfanew + NE->ne_modtab, NULL, FILE_BEGIN) ==
	 INVALID_SET_FILE_POINTER) ||
	(!(ModTab = HeapAlloc(GetProcessHeap(), 0, NE->ne_cmod * sizeof(WORD)))) ||
	(!(ReadFile(hFile, ModTab, NE->ne_cmod * sizeof(WORD), &Read, NULL))) ||
	(Read != (DWORD)NE->ne_cmod * sizeof(WORD))) {
	goto broken;
    }

    /* read imported names table */
    if ((SetFilePointer(hFile, MZ->e_lfanew + NE->ne_imptab, NULL, FILE_BEGIN) ==
	 INVALID_SET_FILE_POINTER) ||
	(!(NameTab = HeapAlloc(GetProcessHeap(), 0, NE->ne_enttab - NE->ne_imptab))) ||
	(!(ReadFile(hFile, NameTab, NE->ne_enttab - NE->ne_imptab, &Read, NULL))) ||
	(Read != (DWORD)NE->ne_enttab - NE->ne_imptab)) {
	goto broken;
    }

    for (i = 0; i < NE->ne_cmod; i++) {
	LPSTR Module;
	Module = &NameTab[ModTab[i]];
	if (!strncmp(&Module[1], "KERNEL", Module[0])) {
	    /* very old windows file */
	    Ret = BINARY_WIN16;
	    goto done;
	}
    }

broken:
    DPRINT1("InternalIsOS2OrOldWin(): Binary file seems to be broken\n");

done:
    HeapFree(GetProcessHeap(), 0, ModTab);
    HeapFree(GetProcessHeap(), 0, NameTab);
    SetFilePointer(hFile, CurPos, NULL, FILE_BEGIN);
    return Ret;
}

static WINAPI DWORD InternalGetBinaryType(HANDLE hFile)
{
    union {
	struct {
	    unsigned char Magic[4];
	    unsigned char Ignored[12];
	    unsigned short Type;
	} Elf;
	struct {
	    unsigned long Magic;
	    unsigned long CpuType;
	    unsigned long CpuSubType;
	    unsigned long FileType;
	} MachO;
	IMAGE_DOS_HEADER MZ;
    } Header;
    char Magic[4];
    DWORD Read;

    if ((SetFilePointer(hFile, 0, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) ||
	(!ReadFile(hFile, &Header, sizeof(Header), &Read, NULL) ||
	 (Read != sizeof(Header)))) {
	return BINARY_UNKNOWN;
    }

    if (!memcmp(Header.Elf.Magic, "\177ELF", sizeof(Header.Elf.Magic))) {
	/* FIXME: we don't bother to check byte order, architecture, etc. */
	switch (Header.Elf.Type) {
	case 2:
	    return BINARY_UNIX_EXE;
	case 3:
	    return BINARY_UNIX_LIB;
	}
	return BINARY_UNKNOWN;
    }

    /* Mach-o File with Endian set to Big Endian or Little Endian*/
    if (Header.MachO.Magic == 0xFEEDFACE || Header.MachO.Magic == 0xCEFAEDFE) {
	switch (Header.MachO.FileType) {
	case 0x8:
	    /* MH_BUNDLE */
	    return BINARY_UNIX_LIB;
	}
	return BINARY_UNKNOWN;
    }

    /* Not ELF, try DOS */
    if (Header.MZ.e_magic == IMAGE_DOS_SIGNATURE) {
	/* We do have a DOS image so we will now try to seek into
	 * the file by the amount indicated by the field
	 * "Offset to extended header" and read in the
	 * "magic" field information at that location.
	 * This will tell us if there is more header information
	 * to read or not.
	 */
	if ((SetFilePointer(hFile, Header.MZ.e_lfanew, NULL, FILE_BEGIN) ==
	     INVALID_SET_FILE_POINTER) ||
	    (!ReadFile(hFile, Magic, sizeof(Magic), &Read, NULL) ||
	     (Read != sizeof(Magic)))) {
	    return BINARY_DOS;
	}

	/* Reading the magic field succeeded so
	 * we will try to determine what type it is.
	 */
	if (!memcmp(Magic, "PE\0\0", sizeof(Magic))) {
	    IMAGE_FILE_HEADER FileHeader;
	    if (!ReadFile(hFile, &FileHeader, sizeof(IMAGE_FILE_HEADER), &Read, NULL) ||
		(Read != sizeof(IMAGE_FILE_HEADER))) {
		return BINARY_DOS;
	    }

	    /* FIXME - detect 32/64 bit */

	    if (FileHeader.Characteristics & IMAGE_FILE_DLL)
		return BINARY_PE_DLL32;
	    return BINARY_PE_EXE32;
	}

	if (!memcmp(Magic, "NE", 2)) {
	    /* This is a Windows executable (NE) header.  This can
	     * mean either a 16-bit OS/2 or a 16-bit Windows or even a
	     * DOS program (running under a DOS extender).  To decide
	     * which, we'll have to read the NE header.
	     */
	    IMAGE_OS2_HEADER NE;
	    if ((SetFilePointer(hFile, Header.MZ.e_lfanew, NULL, FILE_BEGIN) == 1) ||
		!ReadFile(hFile, &NE, sizeof(IMAGE_OS2_HEADER), &Read, NULL) ||
		(Read != sizeof(IMAGE_OS2_HEADER))) {
		/* Couldn't read header, so abort. */
		return BINARY_DOS;
	    }

	    switch (NE.ne_exetyp) {
	    case 2:
		return BINARY_WIN16;
	    case 5:
		return BINARY_DOS;
	    default:
		return InternalIsOS2OrOldWin(hFile, &Header.MZ, &NE);
	    }
	}
	return BINARY_DOS;
    }
    return BINARY_UNKNOWN;
}

/*
 * @implemented
 */
WINAPI BOOL GetBinaryTypeW(LPCWSTR lpApplicationName, LPDWORD lpBinaryType)
{
    HANDLE hFile;
    DWORD BinType;

    if (!lpApplicationName || !lpBinaryType) {
	SetLastError(ERROR_INVALID_PARAMETER);
	return FALSE;
    }

    hFile = CreateFileW(lpApplicationName, GENERIC_READ, FILE_SHARE_READ, NULL,
			OPEN_EXISTING, 0, 0);
    if (hFile == INVALID_HANDLE_VALUE) {
	return FALSE;
    }

    BinType = InternalGetBinaryType(hFile);
    CloseHandle(hFile);

    switch (BinType) {
    case BINARY_UNKNOWN: {
	WCHAR *Dot;

	/*
	 * guess from filename
	 */
	if (!(Dot = wcsrchr(lpApplicationName, L'.'))) {
	    return FALSE;
	}
	if (!lstrcmpiW(Dot, L".COM")) {
	    *lpBinaryType = SCS_DOS_BINARY;
	    return TRUE;
	}
	if (!lstrcmpiW(Dot, L".PIF")) {
	    *lpBinaryType = SCS_PIF_BINARY;
	    return TRUE;
	}
	return FALSE;
    }
    case BINARY_PE_EXE32:
    case BINARY_PE_DLL32: {
	*lpBinaryType = SCS_32BIT_BINARY;
	return TRUE;
    }
    case BINARY_PE_EXE64:
    case BINARY_PE_DLL64: {
	*lpBinaryType = SCS_64BIT_BINARY;
	return TRUE;
    }
    case BINARY_WIN16: {
	*lpBinaryType = SCS_WOW_BINARY;
	return TRUE;
    }
    case BINARY_OS216: {
	*lpBinaryType = SCS_OS216_BINARY;
	return TRUE;
    }
    case BINARY_DOS: {
	*lpBinaryType = SCS_DOS_BINARY;
	return TRUE;
    }
    case BINARY_UNIX_EXE:
    case BINARY_UNIX_LIB: {
	return FALSE;
    }
    }

    DPRINT1("Invalid binary type %u returned!\n", BinType);
    return FALSE;
}

/*
 * @implemented
 */
WINAPI BOOL GetBinaryTypeA(IN LPCSTR lpApplicationName, OUT LPDWORD lpBinaryType)
{
    ANSI_STRING ApplicationNameString;
    UNICODE_STRING ApplicationNameW;
    BOOL StringAllocated = FALSE, Result;
    NTSTATUS Status;

    RtlInitAnsiString(&ApplicationNameString, lpApplicationName);

    if (ApplicationNameString.Length * sizeof(WCHAR) >=
	NtCurrentTeb()->Win32.StaticUnicodeString.MaximumLength) {
	StringAllocated = TRUE;
	Status = RtlAnsiStringToUnicodeString(&ApplicationNameW, &ApplicationNameString,
					      TRUE);
    } else {
	Status = RtlAnsiStringToUnicodeString(
	    &(NtCurrentTeb()->Win32.StaticUnicodeString), &ApplicationNameString, FALSE);
    }

    if (!NT_SUCCESS(Status)) {
	BaseSetLastNTError(Status);
	return FALSE;
    }

    if (StringAllocated) {
	Result = GetBinaryTypeW(ApplicationNameW.Buffer, lpBinaryType);
	RtlFreeUnicodeString(&ApplicationNameW);
    } else {
	Result = GetBinaryTypeW(NtCurrentTeb()->Win32.StaticUnicodeString.Buffer,
				lpBinaryType);
    }

    return Result;
}
