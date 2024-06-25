/*
 * COPYRIGHT:         See COPYING in the top level directory
 * PROJECT:           ReactOS system libraries
 * FILE:              lib/rtl/nls.c
 * PURPOSE:           National Language Support (NLS) functions
 * PROGRAMMERS:       Emanuele Aliberti
 */

/* INCLUDES *****************************************************************/

#include "rtlp.h"

/* GLOBALS *******************************************************************/

PUSHORT NlsUnicodeUpcaseTable = NULL;
PUSHORT NlsUnicodeLowercaseTable = NULL;

/* FUNCTIONS *****************************************************************/

/*
 * @implemented
 */
NTAPI VOID RtlGetDefaultCodePage(OUT PUSHORT AnsiCodePage,
				 OUT PUSHORT OemCodePage)
{
    *AnsiCodePage = 0;
    *OemCodePage = 0;
}

/*
 * @implemented
 */
NTAPI VOID RtlInitCodePageTable(IN PUSHORT TableBase,
				OUT PCPTABLEINFO CodePageTable)
{
    PNLS_FILE_HEADER NlsFileHeader;

    DPRINT("RtlInitCodePageTable() called\n");

    NlsFileHeader = (PNLS_FILE_HEADER) TableBase;

    /* Copy header fields first */
    CodePageTable->CodePage = NlsFileHeader->CodePage;
    CodePageTable->MaximumCharacterSize = NlsFileHeader->MaximumCharacterSize;
    CodePageTable->DefaultChar = NlsFileHeader->DefaultChar;
    CodePageTable->UniDefaultChar = NlsFileHeader->UniDefaultChar;
    CodePageTable->TransDefaultChar = NlsFileHeader->TransDefaultChar;
    CodePageTable->TransUniDefaultChar = NlsFileHeader->TransUniDefaultChar;

    RtlCopyMemory(&CodePageTable->LeadByte,
		  &NlsFileHeader->LeadByte, MAXIMUM_LEADBYTES);

    /* Offset to wide char table is after the header */
    CodePageTable->WideCharTable = TableBase + NlsFileHeader->HeaderSize + 1 +
	TableBase[NlsFileHeader->HeaderSize];

    /* Then multibyte table (256 wchars) follows */
    CodePageTable->MultiByteTable = TableBase + NlsFileHeader->HeaderSize + 1;

    /* Check the presence of glyph table (256 wchars) */
    if (!CodePageTable->MultiByteTable[256])
	CodePageTable->DBCSRanges = CodePageTable->MultiByteTable + 256 + 1;
    else
	CodePageTable->DBCSRanges = CodePageTable->MultiByteTable + 256 + 1 + 256;

    /* Is this double-byte code page? */
    if (*CodePageTable->DBCSRanges) {
	CodePageTable->DBCSCodePage = 1;
	CodePageTable->DBCSOffsets = CodePageTable->DBCSRanges + 1;
    } else {
	CodePageTable->DBCSCodePage = 0;
	CodePageTable->DBCSOffsets = NULL;
    }
}

/*
 * @implemented
 */
NTAPI VOID RtlInitNlsTables(IN PUSHORT AnsiTableBase,
			    IN PUSHORT OemTableBase,
			    IN PUSHORT CaseTableBase,
			    OUT PNLSTABLEINFO NlsTable)
{
    DPRINT("RtlInitNlsTables()called\n");

    if (AnsiTableBase && OemTableBase && CaseTableBase) {
	RtlInitCodePageTable(AnsiTableBase, &NlsTable->AnsiTableInfo);
	RtlInitCodePageTable(OemTableBase, &NlsTable->OemTableInfo);

	NlsTable->UpperCaseTable = CaseTableBase + 2;
	NlsTable->LowerCaseTable = CaseTableBase + 2 + CaseTableBase[1];
    }
}

/*
 * @implemented
 */
NTAPI VOID RtlResetRtlTranslations(IN OPTIONAL PNLSTABLEINFO NlsTable)
{
    UNREFERENCED_PARAMETER(NlsTable);

    extern UCHAR LdrpUnicodeCaseTableData;
    PUSHORT CaseTableBase = (PUSHORT)&LdrpUnicodeCaseTableData;
    NlsUnicodeUpcaseTable = CaseTableBase + 2;
    NlsUnicodeLowercaseTable = CaseTableBase + 2 + CaseTableBase[1];
}

/*
 * @implemented
 */
NTAPI NTSTATUS RtlMultiByteToUnicodeN(OUT PWCHAR UnicodeString,
				      IN ULONG UnicodeSize,
				      OUT OPTIONAL PULONG ResultSize,
				      IN PCSTR MbString,
				      IN ULONG MbSize)
{
    ULONG Size;
    NTSTATUS Status = RtlUTF8ToUnicodeN(UnicodeString, UnicodeSize,
					&Size, MbString, MbSize);
    if (ResultSize) {
	*ResultSize = Size;
    }
    return Status;
}

/*
 * @implemented
 */
NTAPI NTSTATUS RtlConsoleMultiByteToUnicodeN(OUT PWCHAR UnicodeString,
					     IN ULONG UnicodeSize,
					     OUT PULONG ResultSize,
					     IN PCSTR MbString,
					     IN ULONG MbSize,
					     OUT PULONG Unknown)
{
    *Unknown = 1;
    return RtlMultiByteToUnicodeN(UnicodeString, UnicodeSize, ResultSize,
				  MbString, MbSize);
}

/*
 * @implemented
 */
NTAPI NTSTATUS RtlMultiByteToUnicodeSize(OUT PULONG UnicodeSize,
					 IN PCSTR MbString,
					 IN ULONG MbSize)
{
    return RtlUTF8ToUnicodeN(NULL, ULONG_MAX, UnicodeSize, MbString, MbSize);
}

/*
 * @implemented
 */
NTAPI NTSTATUS RtlOemToUnicodeN(OUT PWCHAR UnicodeString,
				IN ULONG UnicodeSize,
				OUT OPTIONAL PULONG ResultSize,
				IN PCCH OemString,
				IN ULONG OemSize)
{
    return RtlMultiByteToUnicodeN(UnicodeString, UnicodeSize, ResultSize,
				  OemString, OemSize);
}

/*
 * @implemented
 */
NTAPI NTSTATUS RtlUnicodeToMultiByteN(OUT PCHAR MbString,
				      IN ULONG MbSize,
				      OUT OPTIONAL PULONG ResultSize,
				      IN PCWCH UnicodeString,
				      IN ULONG UnicodeSize)
{
    ULONG Utf8Size;
    NTSTATUS Status = RtlUnicodeToUTF8N(MbString, MbSize, &Utf8Size,
					UnicodeString, UnicodeSize);
    if (ResultSize) {
	*ResultSize = Utf8Size;
    }
    return Status;
}

/*
 * @implemented
 */
NTAPI NTSTATUS RtlUnicodeToMultiByteSize(OUT PULONG MbSize,
					 IN PCWCH UnicodeString,
					 IN ULONG UnicodeSize)
{
    return RtlUnicodeToUTF8N(NULL, ULONG_MAX, MbSize,
			     UnicodeString, UnicodeSize);
}

/*
 * @implemented
 */
NTAPI NTSTATUS RtlUnicodeToOemN(OUT PCHAR OemString,
				IN ULONG OemSize,
				OUT OPTIONAL PULONG ResultSize,
				IN PCWCH UnicodeString,
				IN ULONG UnicodeSize)
{
    return RtlUnicodeToMultiByteN(OemString, OemSize, ResultSize,
				  UnicodeString, UnicodeSize);
}

/*
 * @implemented
 * @note Double-byte code pages are not supported.
 */
NTAPI NTSTATUS RtlCustomCPToUnicodeN(IN PCPTABLEINFO CustomCP,
				     OUT PWCHAR UnicodeString,
				     IN ULONG UnicodeSize,
				     OUT OPTIONAL PULONG ResultSize,
				     IN PCHAR CustomString,
				     IN ULONG CustomSize)
{
    ULONG Size = 0;
    ULONG i;

    if (CustomCP->DBCSCodePage) {
	return STATUS_NOT_SUPPORTED;
    }

    /* single-byte code page */
    if (CustomSize > (UnicodeSize / sizeof(WCHAR)))
	Size = UnicodeSize / sizeof(WCHAR);
    else
	Size = CustomSize;

    if (ResultSize)
	*ResultSize = Size * sizeof(WCHAR);

    for (i = 0; i < Size; i++) {
	*UnicodeString = CustomCP->MultiByteTable[(UCHAR) * CustomString];
	UnicodeString++;
	CustomString++;
    }
    return STATUS_SUCCESS;
}

/*
 * @implemented
 */
NTAPI NTSTATUS RtlUnicodeToCustomCPN(IN PCPTABLEINFO CustomCP,
				     OUT PCHAR CustomString,
				     IN ULONG CustomSize,
				     OUT PULONG ResultSize OPTIONAL,
				     IN PWCHAR UnicodeString,
				     IN ULONG UnicodeSize)
{
    ULONG Size = 0;
    ULONG i;

    if (CustomCP->DBCSCodePage) {
	return STATUS_NOT_SUPPORTED;
    }

    /* single-byte code page */
    if (UnicodeSize > (CustomSize * sizeof(WCHAR)))
	Size = CustomSize;
    else
	Size = UnicodeSize / sizeof(WCHAR);

    if (ResultSize)
	*ResultSize = Size;

    for (i = 0; i < Size; i++) {
	*CustomString = ((PCHAR)CustomCP->WideCharTable)[*UnicodeString];
	CustomString++;
	UnicodeString++;
    }
    return STATUS_SUCCESS;
}

/*
 * @implemented
 */
WCHAR RtlpDowncaseUnicodeChar(IN WCHAR Source)
{
    USHORT Offset;

    if (Source < L'A')
	return Source;

    if (Source <= L'Z')
	return Source + (L'a' - L'A');

    if (Source < 0x80)
	return Source;

    Offset = ((USHORT) Source >> 8);
    DPRINT("Offset: %hx\n", Offset);

    Offset = NlsUnicodeLowercaseTable[Offset];
    DPRINT("Offset: %hx\n", Offset);

    Offset += (((USHORT) Source & 0x00F0) >> 4);
    DPRINT("Offset: %hx\n", Offset);

    Offset = NlsUnicodeLowercaseTable[Offset];
    DPRINT("Offset: %hx\n", Offset);

    Offset += ((USHORT) Source & 0x000F);
    DPRINT("Offset: %hx\n", Offset);

    Offset = NlsUnicodeLowercaseTable[Offset];
    DPRINT("Offset: %hx\n", Offset);

    DPRINT("Result: %hx\n", (USHORT)(Source + (SHORT) Offset));

    return Source + (SHORT) Offset;
}

/*
 * @implemented
 */
NTAPI WCHAR RtlDowncaseUnicodeChar(IN WCHAR Source)
{
    return RtlpDowncaseUnicodeChar(Source);
}

/*
 * @implemented
 */
WCHAR RtlpUpcaseUnicodeChar(IN WCHAR Source)
{
    USHORT Offset;

    if (Source < 'a')
	return Source;

    if (Source <= 'z')
	return (Source - ('a' - 'A'));

    Offset = ((USHORT) Source >> 8) & 0xFF;
    Offset = NlsUnicodeUpcaseTable[Offset];

    Offset += ((USHORT) Source >> 4) & 0xF;
    Offset = NlsUnicodeUpcaseTable[Offset];

    Offset += ((USHORT) Source & 0xF);
    Offset = NlsUnicodeUpcaseTable[Offset];

    return Source + (SHORT) Offset;
}

/*
 * @implemented
 */
NTAPI WCHAR RtlUpcaseUnicodeChar(IN WCHAR Source)
{
    return RtlpUpcaseUnicodeChar(Source);
}

/*
 * @implemented
 */
NTAPI CHAR RtlUpperChar(IN CHAR Source)
{
    /* Check for simple ANSI case */
    if (Source <= 'z') {
	/* Check for simple downcase a-z case */
	if (Source >= 'a') {
	    /* Just XOR with the difference */
	    return Source ^ ('a' - 'A');
	}
    }
    /* Otherwise return the same char */
    return Source;
}

/*
 * @implemented
 */
NTAPI NTSTATUS RtlUpcaseUnicodeToCustomCPN(IN PCPTABLEINFO CustomCP,
					   OUT PCHAR CustomString,
					   IN ULONG CustomSize,
					   OUT PULONG ResultSize OPTIONAL,
					   IN PWCHAR UnicodeString,
					   IN ULONG UnicodeSize)
{
    WCHAR UpcaseChar;
    ULONG Size = 0;
    ULONG i;

    if (CustomCP->DBCSCodePage) {
	return STATUS_NOT_SUPPORTED;
    }

    /* single-byte code page */
    if (UnicodeSize > (CustomSize * sizeof(WCHAR)))
	Size = CustomSize;
    else
	Size = UnicodeSize / sizeof(WCHAR);

    if (ResultSize)
	*ResultSize = Size;

    for (i = 0; i < Size; i++) {
	UpcaseChar = RtlpUpcaseUnicodeChar(*UnicodeString);
	*CustomString = ((PCHAR) CustomCP->WideCharTable)[UpcaseChar];
	++CustomString;
	++UnicodeString;
    }

    return STATUS_SUCCESS;
}

/*
 * @implemented
 */
NTAPI NTSTATUS RtlUpcaseUnicodeToMultiByteN(OUT PCHAR MbString,
					    IN ULONG MbSize,
					    OUT PULONG ResultSize OPTIONAL,
					    IN PCWCH UnicodeString,
					    IN ULONG UnicodeSize)
{
    NTSTATUS Status = STATUS_SUCCESS;
    WCHAR UpcaseChar;
    ULONG SizeWritten = 0;

    while (SizeWritten < MbSize) {
	UpcaseChar = RtlpUpcaseUnicodeChar(*UnicodeString);
	CHAR Buffer[4];
	ULONG CodepointSize;
	Status = RtlUnicodeToUTF8N(Buffer, sizeof(Buffer), &CodepointSize,
				   &UpcaseChar, sizeof(WCHAR));
	if (!NT_SUCCESS(Status)) {
	    break;
	}
	if (SizeWritten + CodepointSize > MbSize) {
	    break;
	}
	for (ULONG i = 0; i < CodepointSize; i++) {
	    *MbString = Buffer[i];
	    MbString++;
	}
	SizeWritten += CodepointSize;
	UnicodeString++;
    }

    if (ResultSize) {
	*ResultSize = SizeWritten;
    }

    return Status;
}

/*
 * @implemented
 */
NTAPI NTSTATUS RtlUpcaseUnicodeToOemN(OUT PCHAR OemString,
				      IN ULONG OemSize,
				      OUT PULONG ResultSize OPTIONAL,
				      IN PCWCH UnicodeString,
				      IN ULONG UnicodeSize)
{
    return RtlUpcaseUnicodeToMultiByteN(OemString, OemSize, ResultSize,
					UnicodeString, UnicodeSize);
}

NTAPI NTSTATUS NtQueryDefaultLocale(IN BOOLEAN UserProfile,
				    OUT PLCID DefaultLocaleId)
{
    return UserProfile ? NtCurrentPeb()->SessionDefaultLocale : SharedUserData->DefaultLocale;
}
