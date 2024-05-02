#include "ntcmd.h"
#include "ntdef.h"
#include "ntstatus.h"

/*
 *****************************************************************************
 * GetFullPath - Get a full path.
 *
 * FileName: File name
 * FullPath: String for full path
 * FullPathSize: Size of the output buffer (in bytes)
 * AddSlash: Add slash to the end of string
 *
 * Returns: NT Status
 *****************************************************************************
 */
NTSTATUS GetFullPath(IN PCSTR FileName,
		     OUT PWSTR FullPath,
		     IN ULONG FullPathSize,
		     IN BOOL AddSlash)
{
    UNICODE_STRING UnicodeString;
    ANSI_STRING AnsiString;
    WCHAR CurrentDirectory[MAX_PATH];
    RtlCliGetCurrentDirectory(CurrentDirectory);

    if (NULL == FileName || NULL == FullPath || FullPathSize == 0) {
	return STATUS_INVALID_PARAMETER;
    }

    if ((strlen(FileName) > 1) && FileName[1] == ':') {
	RtlInitAnsiString(&AnsiString, FileName);
	RtlAnsiStringToUnicodeString(&UnicodeString, &AnsiString, TRUE);

	wcscpy_s(FullPath, MAX_PATH, UnicodeString.Buffer);
	if (AddSlash) {
	    wcscat_s(FullPath, MAX_PATH, L"\\");
	}

	RtlFreeUnicodeString(&UnicodeString);
    } else {
	RtlInitAnsiString(&AnsiString, FileName);
	NTSTATUS Status = RtlAnsiStringToUnicodeString(&UnicodeString,
						       &AnsiString, TRUE);
	if (!NT_SUCCESS(Status)) {
	    return Status;
	}

	wcscpy_s(FullPath, MAX_PATH, CurrentDirectory);
	if (FullPath[wcslen(FullPath) - 1] != L'\\') {
	    wcscat_s(FullPath, MAX_PATH, L"\\");
	}
	wcscat_s(FullPath, MAX_PATH, UnicodeString.Buffer);
	if (AddSlash) {
	    wcscat_s(FullPath, MAX_PATH, L"\\");
	}

	RtlFreeUnicodeString(&UnicodeString);
    }
    return STATUS_SUCCESS;
}

// Argument processing functions:
char *xstrtok(IN PCHAR s, IN PCSTR ct, OUT PCHAR *next_token)
{
    char *sbegin = s, *send;
    if (!sbegin) {
	return NULL;
    }
    sbegin += strspn(sbegin, ct);
    if (*sbegin == '\0') {
	*next_token = NULL;
	return NULL;
    }
    send = strpbrk(sbegin, ct);
    if (send && *send != '\0') {
	*send++ = '\0';
    }
    *next_token = send;
    return sbegin;
}

ULONG StringToArguments(IN OUT CHAR *Cmd, IN ULONG Bufsize, IN ULONG MaxArgs,
			OUT PCHAR *xargv)
{
    if (!MaxArgs) {
	return 0;
    }

    BOOL dq = FALSE, sq = FALSE;
    char *p = Cmd;

    // 0x01 as a separator
    do {
	switch (*p) {
	case ' ':
	    if (!sq && !dq) {
		*p = '\1';
	    }
	    break;
	case '\"':
	    dq = !dq;
	    *p = '\1';
	    break;
	case '\'':
	    sq = !sq;
	    *p = '\1';
	    break;
	default:
	    break;
	}
	p++;
    } while (*p && p < &Cmd[Bufsize]);

    ULONG xargc = 0;

    PCHAR NextToken = NULL;
    p = xstrtok(Cmd, "\1", &NextToken);
    if (p) {
	xargv[xargc++] = p;
	if (MaxArgs == 1) {
	    return 1;
	}
	p = NextToken;
	while (p && *p) {
	    p = xstrtok(p, "\1", &NextToken);
	    xargv[xargc++] = p;
	    if (xargc >= MaxArgs) {
		return xargc;
	    }
	    p = NextToken;
	}
	return xargc;
    }

    return 0;
}

/******************************************************************************\
 * GetFileAttributesNt - Get File Attributes
 * fname: File name
\******************************************************************************/

ULONG GetFileAttributesNt(PCWSTR filename)
{
    OBJECT_ATTRIBUTES oa;
    FILE_BASIC_INFORMATION fbi;
    UNICODE_STRING nt_filename;

    RtlDosPathNameToNtPathName_U(filename, &nt_filename, NULL, NULL);
    InitializeObjectAttributes(&oa, &nt_filename, OBJ_CASE_INSENSITIVE, 0, 0);

    fbi.FileAttributes = 0;
    NtQueryAttributesFile(&oa, &fbi);

    return fbi.FileAttributes;
}

/******************************************************************************\
 * FolderExists - Check if folder exists
 * fFile: Folder
\******************************************************************************/

BOOL FolderExists(PCWSTR FolderName)
{
    UNICODE_STRING NtFileName;
    if (!RtlDosPathNameToNtPathName_U(FolderName, &NtFileName, NULL, NULL)) {
	return FALSE;
    }
    OBJECT_ATTRIBUTES ObjAttr;
    InitializeObjectAttributes(&ObjAttr, &NtFileName, OBJ_CASE_INSENSITIVE, 0, 0);
    FILE_BASIC_INFORMATION FileInfo;
    NTSTATUS Status = NtQueryAttributesFile(&ObjAttr, &FileInfo);
    BOOLEAN Ret = NT_SUCCESS(Status) && (FileInfo.FileAttributes & FILE_ATTRIBUTE_DIRECTORY);
    RtlFreeUnicodeString(&NtFileName);
    return Ret;
}

/******************************************************************************\
 * FileExists - Checks if file exists
 * filename: File name
\******************************************************************************/

BOOL FileExists(PCWSTR FileName)
{
    UNICODE_STRING NtFileName;
    RtlDosPathNameToNtPathName_U(FileName, &NtFileName, NULL, NULL);
    OBJECT_ATTRIBUTES ObjAttr;
    InitializeObjectAttributes(&ObjAttr, &NtFileName, OBJ_CASE_INSENSITIVE, 0, 0);
    FILE_BASIC_INFORMATION FileInfo;
    NTSTATUS Status = NtQueryAttributesFile(&ObjAttr, &FileInfo);
    RtlFreeUnicodeString(&NtFileName);
    return NT_SUCCESS(Status);
}

HANDLE InitHeapMemory(void)
{
    RTL_HEAP_PARAMETERS sHeapDef;
    HANDLE hHeap;

    // Init Heap Memory
    memset(&sHeapDef, 0, sizeof(RTL_HEAP_PARAMETERS));
    sHeapDef.Length = sizeof(RTL_HEAP_PARAMETERS);
    hHeap = RtlCreateHeap(HEAP_GROWABLE, NULL, 0x100000, 0x1000, NULL,
			  &sHeapDef);

    return hHeap;
}

BOOLEAN DeinitHeapMemory(HANDLE hHeap)
{
    PVOID pRet;

    pRet = RtlDestroyHeap(hHeap);
    if (pRet == NULL)
	return TRUE;

    return FALSE;
}

BOOLEAN AppendString(WCHAR *pszInput,
		     WCHAR *pszAppend)
{
    int i, nAppendIndex;

    for (i = 0;; i++) {
	if (pszInput[i] == 0x0000) {
	    break;
	}
    }

    nAppendIndex = 0;
    for (;;) {
	if (pszAppend[nAppendIndex] == 0x0000) {
	    break;
	}
	pszInput[i] = pszAppend[nAppendIndex];

	nAppendIndex++;
	i++;
    }

    pszInput[i] = 0x0000;	// set end of string.

    return TRUE;
}

UINT GetStringLength(WCHAR *pszInput)
{
    int i;

    for (i = 0;; i++) {
	if (pszInput[i] == 0x0000) {
	    break;
	}
    }

    return i;
}

// Note: This function allocates memory for "UnicodeString" variable.
NTSTATUS FillUnicodeStringWithAnsi(OUT PUNICODE_STRING UnicodeString,
				   IN PCHAR String)
{
    ANSI_STRING AnsiString;
    RtlInitAnsiString(&AnsiString, String);
    return RtlAnsiStringToUnicodeString(UnicodeString, &AnsiString, TRUE);
}

PCSTR RtlCliStatusToErrorMessage(IN NTSTATUS Status)
{
    static CHAR Buffer[128];
    switch (Status) {
    case STATUS_SUCCESS:
	return "success";
    case STATUS_UNSUCCESSFUL:
	return "failed";
    case STATUS_INVALID_PARAMETER:
	return "invalid parameter";
    case STATUS_OBJECT_NAME_NOT_FOUND:
    case STATUS_OBJECT_PATH_NOT_FOUND:
	return "no such file or directory";
    case STATUS_OBJECT_NAME_INVALID:
    case STATUS_OBJECT_PATH_INVALID:
	return "invalid path";
    case STATUS_OBJECT_NAME_COLLISION:
    case STATUS_OBJECT_NAME_EXISTS:
	return "file exists";
    case STATUS_IO_DEVICE_ERROR:
    case STATUS_DEVICE_DATA_ERROR:
    case STATUS_DEVICE_HARDWARE_ERROR:
	return "input/output error";
    case STATUS_TIMEOUT:
    case STATUS_IO_TIMEOUT:
	return "timed out";
    case STATUS_DEVICE_BUSY:
	return "device busy";
    case STATUS_NO_MEMORY:
    case STATUS_INSUFFICIENT_RESOURCES:
	return "out of memory";
    case STATUS_DISK_FULL:
	return "disk full";
    case STATUS_DISK_CORRUPT_ERROR:
	return "disk corrupt";
    default:
	if (NT_SUCCESS(Status)) {
	    snprintf(Buffer, sizeof(Buffer), "success (status 0x%08x)", Status);
	} else {
	    snprintf(Buffer, sizeof(Buffer), "%s 0x%08x",
		     NT_WARNING(Status) ? "warning" : "error", Status);
	}
	return Buffer;
    }
}
