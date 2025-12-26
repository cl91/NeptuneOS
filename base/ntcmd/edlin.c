#include "ntcmd.h"

typedef struct _LINE_BUFFER {
    WCHAR **Lines;
    ULONG Count;
} LINE_BUFFER, *PLINE_BUFFER;

static VOID PrintLine(PLINE_BUFFER Lb, ULONG Number)
{
    if (Number == 0 || Number > Lb->Count) {
        RtlCliDisplayString("?\n");
        return;
    }
    RtlCliDisplayString("%ws\n", Lb->Lines[Number - 1]);
}

static VOID PrintAll(PLINE_BUFFER Lb)
{
    for (ULONG Index = 0; Index < Lb->Count; Index++) {
        RtlCliDisplayString("%u: %ws\n", Index + 1, Lb->Lines[Index]);
    }
}

static VOID EditLine(PLINE_BUFFER Lb, ULONG Number, const WCHAR *Text)
{
    if (Number == 0 || Number > Lb->Count) {
        RtlCliDisplayString("?\n");
        return;
    }
    ULONG NumWchars = wcslen(Text) + 1;
    WCHAR *NewLine = RtlAllocateHeap(RtlGetProcessHeap(), 0,
				     NumWchars * sizeof(WCHAR));
    if (!NewLine) {
	RtlCliDisplayString("No memory.\n");
	return;
    }
    wcscpy_s(NewLine, NumWchars, Text);
    if (Lb->Lines[Number - 1]) {
	RtlFreeHeap(RtlGetProcessHeap(), 0, Lb->Lines[Number - 1]);
    }
    Lb->Lines[Number - 1] = NewLine;
    RtlCliDisplayString("\n");
}

static NTSTATUS LoadFile(PCWSTR FileName, PLINE_BUFFER Lb)
{
    HANDLE FileHandle;
    IO_STATUS_BLOCK IoStatus;

    NTSTATUS Status = OpenFile(&FileHandle, FileName, TRUE, FALSE);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    FILE_STANDARD_INFORMATION StdInfo;
    Status = NtQueryInformationFile(FileHandle, &IoStatus, &StdInfo,
				    sizeof(StdInfo), FileStandardInformation);

    if (!NT_SUCCESS(Status)) {
        NtClose(FileHandle);
        return Status;
    }

    ULONG FileSize = StdInfo.EndOfFile.LowPart;
    CHAR *FileBuffer = RtlAllocateHeap(RtlGetProcessHeap(), 0, FileSize + 2);

    Status = ReadFile(FileHandle, FileBuffer, FileSize, NULL);

    NtClose(FileHandle);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    FileBuffer[FileSize] = '\0';

    // Convert to lines
    ULONG LineCount = 1;
    for (ULONG i = 0; i < FileSize; i++) {
        if (FileBuffer[i] == '\n') {
	    LineCount++;
	}
    }

    Lb->Lines = RtlAllocateHeap(RtlGetProcessHeap(), 0, sizeof(WCHAR*) * LineCount);
    if (!Lb->Lines) {
	RtlFreeHeap(RtlGetProcessHeap(), 0, FileBuffer);
	return STATUS_NO_MEMORY;
    }
    Lb->Count = LineCount;

    CHAR *Cursor = FileBuffer;
    for (ULONG i = 0; i < LineCount; i++) {
        CHAR *LineStart = Cursor;
        while (*Cursor != '\n' && *Cursor != '\0') {
	    Cursor++;
	}
        ULONG Len = Cursor - LineStart;

        WCHAR *Ws = RtlAllocateHeap(RtlGetProcessHeap(), 0, (Len + 1) * sizeof(WCHAR));
	if (!Ws) {
	    for (ULONG j = 0; j < i; j++) {
		RtlFreeHeap(RtlGetProcessHeap(), 0, Lb->Lines[j]);
		RtlFreeHeap(RtlGetProcessHeap(), 0, Lb->Lines);
		RtlFreeHeap(RtlGetProcessHeap(), 0, FileBuffer);
		return STATUS_NO_MEMORY;
	    }
	}
        for (ULONG j = 0; j < Len; j++) {
	    Ws[j] = (WCHAR)LineStart[j];
	}
        Ws[Len] = L'\0';
        Lb->Lines[i] = Ws;

        if (*Cursor == '\n') {
	    Cursor++;
	}
    }

    RtlFreeHeap(RtlGetProcessHeap(), 0, FileBuffer);
    return STATUS_SUCCESS;
}

static NTSTATUS SaveFile(PCWSTR FileName, PLINE_BUFFER Lb)
{
    HANDLE FileHandle;
    IO_STATUS_BLOCK IoStatus;

    NTSTATUS Status = OpenFile(&FileHandle, FileName, TRUE, TRUE);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    LARGE_INTEGER ByteOffset;
    ByteOffset.QuadPart = 0;

    for (ULONG i = 0; i < Lb->Count; i++) {
        CHAR Utf8[2048];
        ULONG Utf8Len = 0;

        for (ULONG k = 0; Lb->Lines[i][k] != 0; k++) {
            Utf8[Utf8Len++] = (CHAR)Lb->Lines[i][k];
	}
        Utf8[Utf8Len++] = '\n';

        Status = NtWriteFile(FileHandle, NULL, NULL, NULL, &IoStatus,
			     Utf8, Utf8Len, &ByteOffset, NULL);

        if (!NT_SUCCESS(Status)) {
	    break;
	}

        ByteOffset.QuadPart += Utf8Len;
    }

    NtClose(FileHandle);
    return Status;
}

NTSTATUS RtlCliEditLineFile(IN PCSTR FileName)
{
    WCHAR FileNameW[260] = {};
    NTSTATUS Status = GetFullPath(FileName, FileNameW, sizeof(FileNameW), FALSE);
    if (!NT_SUCCESS(Status)) {
	RtlCliDisplayString("Failed to get full path for %s: %s\n",
			    FileName, RtlCliStatusToErrorMessage(Status));
	return Status;
    }

    LINE_BUFFER Lb = {0};
    Status = LoadFile(FileNameW, &Lb);
    if (!NT_SUCCESS(Status)) {
        RtlCliDisplayString("Failed to open file %s: %s\n",
			    FileName, RtlCliStatusToErrorMessage(Status));
        return Status;
    }

    RtlCliDisplayString("Commands:\n");
    RtlCliDisplayString("  n          – print line n\n");
    RtlCliDisplayString("  n text...  – replace line n\n");
    RtlCliDisplayString("  p          – print all lines\n");
    RtlCliDisplayString("  s          – save\n");
    RtlCliDisplayString("  q          – quit\n");

    PCSTR Input;
    while (1) {
        RtlCliDisplayString("* ");
        if (!(Input = RtlCliGetLine(hKeyboard))) {
	    break;
	}

        if (Input[0] == 'q') {
	    RtlCliDisplayString("\n");
	    break;
	}

        if (Input[0] == 'p') {
            PrintAll(&Lb);
            continue;
        }

        if (Input[0] == 's') {
            Status = SaveFile(FileNameW, &Lb);
            if (!NT_SUCCESS(Status))
                RtlCliDisplayString("Save failed (%s)\n",
				    RtlCliStatusToErrorMessage(Status));
            else
                RtlCliDisplayString("Saved.\n");
            continue;
        }

	ULONG LineNumber = 0;
	RtlCharToInteger(Input, 10, &LineNumber);
        if (LineNumber > 0) {
            // find first space
            char *SpacePtr = strchr(Input, ' ');
            if (!SpacePtr) {
                PrintLine(&Lb, LineNumber);
                continue;
            }
            while (*SpacePtr == ' ') SpacePtr++;

            WCHAR NewText[1024];
	    ULONG BytesWritten = 0;
            RtlUTF8ToUnicodeN(NewText, sizeof(NewText), &BytesWritten,
			      SpacePtr, strlen(SpacePtr) + 1);

            // Strip trailing newline
            size_t L = wcslen(NewText);
            if (L > 0 && NewText[L - 1] == L'\n')
                NewText[L - 1] = 0;

            EditLine(&Lb, LineNumber, NewText);
            continue;
        }

        RtlCliDisplayString("?\n");
    }

    return STATUS_SUCCESS;
}
