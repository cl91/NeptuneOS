#include "precomp.h"

char *xargv[BUFFER_SIZE];
unsigned int xargc;

/*
 *****************************************************************************
 * GetFullPath - Get a full path.
 *
 * filename: File name
 * out: String for full path
 * out_size: Size of the output buffer (in bytes)
 * add_slash: Add slash to the end of string
 *
 * Returns: TRUE or FALSE
 *****************************************************************************
 */
BOOL GetFullPath(IN PCSTR filename,
		 OUT PWSTR out,
		 IN ULONG out_size,
		 IN BOOL add_slash)
{
    UNICODE_STRING us;
    ANSI_STRING as;
    WCHAR cur_path[MAX_PATH];
    RtlCliGetCurrentDirectory(cur_path);

    if (NULL == filename || NULL == out || out_size == 0) {
	return FALSE;
    }

    if ((strlen(filename) > 1) && filename[1] == ':') {
	RtlInitAnsiString(&as, filename);
	RtlAnsiStringToUnicodeString(&us, &as, TRUE);

	wcscpy_s(out, MAX_PATH, us.Buffer);
	if (add_slash) {
	    wcscat_s(out, MAX_PATH, L"\\");
	}

	RtlFreeUnicodeString(&us);
	RtlFreeAnsiString(&as);
    } else {
	RtlInitAnsiString(&as, filename);
	RtlAnsiStringToUnicodeString(&us, &as, TRUE);

	wcscpy_s(out, MAX_PATH, cur_path);
	if (out[wcslen(out) - 1] != L'\\') {
	    wcscat_s(out, MAX_PATH, L"\\");
	}
	wcscat_s(out, MAX_PATH, us.Buffer);
	if (add_slash) {
	    wcscat_s(out, MAX_PATH, L"\\");
	}

	RtlFreeUnicodeString(&us);
	RtlFreeAnsiString(&as);
    }
    return TRUE;
}

// Argument processing functions:

char *xargv[BUFFER_SIZE];
unsigned int xargc;

char *xstrtok(char *s, const char *ct)
{
    static char *old_strtok;
    char *sbegin, *send;
    sbegin = s ? s : old_strtok;
    if (!sbegin) {
	return NULL;
    }
    sbegin += strspn(sbegin, ct);
    if (*sbegin == '\0') {
	old_strtok = NULL;
	return (NULL);
    }
    send = strpbrk(sbegin, ct);
    if (send && *send != '\0') {
	*send++ = '\0';
    }
    old_strtok = send;
    return (sbegin);
}

UINT StringToArguments(CHAR *str)
{
    BOOL q = FALSE;
    char *p;

    p = str;

    // 0x01 as a separator

    do {
	switch (*p) {
	case ' ':
	    if (q) {
		;
	    } else {
		*p = '\1';
	    }
	    break;
	case '\"':
	    if (q) {
		q = FALSE;
	    } else {
		q = TRUE;
	    }
	    *p = '\1';
	    break;
	default:

	    break;
	}
	p++;
    } while (*p);

    xargc = 0;

    p = xstrtok(str, "\1");
    if (p) {
	xargv[++xargc] = p;
	while (p != NULL) {
	    p = xstrtok(NULL, "\1");
	    xargv[++xargc] = p;
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
    InitializeObjectAttributes(&oa, &nt_filename, OBJ_CASE_INSENSITIVE, 0,
			       0);

    fbi.FileAttributes = 0;
    NtQueryAttributesFile(&oa, &fbi);

    return fbi.FileAttributes;
}

/******************************************************************************\
 * FolderExists - Check if folder exists
 * fFile: Folder
\******************************************************************************/

BOOL FolderExists(PCWSTR foldername)
{
    BOOL retval = FALSE;
    UNICODE_STRING u_filename, nt_filename;
    FILE_BASIC_INFORMATION fbi;
    OBJECT_ATTRIBUTES oa;
    NTSTATUS st;

    RtlInitUnicodeString(&u_filename, foldername);
    RtlDosPathNameToNtPathName_U(u_filename.Buffer, &nt_filename, NULL,
				 NULL);
    RtlFreeUnicodeString(&u_filename);

    InitializeObjectAttributes(&oa, &nt_filename, OBJ_CASE_INSENSITIVE, 0,
			       0);
    st = NtQueryAttributesFile(&oa, &fbi);

    retval = NT_SUCCESS(st);

    if (retval && (fbi.FileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
	return TRUE;
    }
    return FALSE;
}

/******************************************************************************\
 * FileExists - Checks if file exists
 * filename: File name
\******************************************************************************/

BOOL FileExists(PCWSTR filename)
{
    UNICODE_STRING u_filename, nt_filename;
    FILE_BASIC_INFORMATION fbi;
    OBJECT_ATTRIBUTES oa;
    NTSTATUS st;

    RtlInitUnicodeString(&u_filename, filename);
    RtlDosPathNameToNtPathName_U(u_filename.Buffer, &nt_filename, NULL,
				 NULL);
    RtlFreeUnicodeString(&u_filename);

    InitializeObjectAttributes(&oa, &nt_filename, OBJ_CASE_INSENSITIVE, 0,
			       0);
    st = NtQueryAttributesFile(&oa, &fbi);

    return NT_SUCCESS(st);
}

BOOLEAN DisplayString(WCHAR * pwszData)
{
    UNICODE_STRING ustrData;
    BOOLEAN bRet;

    bRet = SetUnicodeString(&ustrData, pwszData);

    if (bRet == FALSE)
	return FALSE;

    NtDisplayString(&ustrData);

    return TRUE;
}

BOOLEAN SetUnicodeString(UNICODE_STRING * pustrRet, WCHAR * pwszData)
{
    if (pustrRet == NULL || pwszData == NULL) {
	return FALSE;
    }

    pustrRet->Buffer = pwszData;
    pustrRet->Length = wcslen(pwszData) * sizeof(WCHAR);
    pustrRet->MaximumLength = pustrRet->Length + sizeof(WCHAR);

    return TRUE;
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

UINT GetStringLength(WCHAR * pszInput)
{
    int i;

    for (i = 0;; i++) {
	if (pszInput[i] == 0x0000) {
	    break;
	}
    }

    return i;
}

// Note: This function allocates memory for "us" variable.
void FillUnicodeStringWithAnsi(OUT PUNICODE_STRING us,
			       IN PCHAR as)
{
    ANSI_STRING ansi_string;

    RtlInitAnsiString(&ansi_string, as);

    if (!NT_SUCCESS(RtlAnsiStringToUnicodeString(us, &ansi_string, TRUE))) {
	RtlCliDisplayString("RtlAnsiStringToUnicodeString() failed\n");
	return;
    }

    RtlFreeAnsiString(&ansi_string);
    return;
}
