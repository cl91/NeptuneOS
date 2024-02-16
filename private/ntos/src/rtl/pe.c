#include <ntos.h>

NTSTATUS RtlImageNtHeaderEx(IN PIO_FILE_CONTROL_BLOCK Fcb,
			    OUT PIMAGE_NT_HEADERS *OutHeaders,
			    OUT ULONG64 *NtHeaderOffset)
{
    assert(Fcb);
    assert(OutHeaders);
    assert(NtHeaderOffset);
    *OutHeaders = NULL;

    /* Make sure the image size is at least big enough for the DOS header */
    if (Fcb->FileSize < sizeof(IMAGE_DOS_HEADER)) {
	DPRINT1("Fcb %p file size 0x%zx too small\n",
		Fcb, Fcb->FileSize);
	return STATUS_INVALID_IMAGE_FORMAT;
    }

    /* Check if the DOS Signature matches */
    PIMAGE_DOS_HEADER DosHeader = NULL;
    NTSTATUS Status = CcMapData(Fcb, 0, sizeof(IMAGE_DOS_HEADER),
				NULL, (PVOID *)&DosHeader);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }
    assert(DosHeader);

    if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        /* Not a valid DOS header */
        DPRINT1("Invalid image DOS signature (expected 0x%x found 0x%x)\n",
		IMAGE_DOS_SIGNATURE, DosHeader->e_magic);
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    if (DosHeader->e_lfanew <= 0) {
        DPRINT1("Invalid DOS header with e_lfanew = %d\n", DosHeader->e_lfanew);
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    /* Get the offset to the NT headers (and copy from LONG to ULONG) */
    *NtHeaderOffset = DosHeader->e_lfanew;

    /* The offset must not be larger than 256MB, as a hard-coded check.
       In Windows this check is only done in user mode, not in kernel mode,
       but it shouldn't harm to have it anyway. Note that without this check,
       other overflow checks would become necessary! */
    if (*NtHeaderOffset >= (256 * 1024 * 1024)) {
        DPRINT1("NT headers offset is larger than 256MB!\n");
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    /* Make sure the file header fits into the size */
    if (*NtHeaderOffset >= Fcb->FileSize) {
	DPRINT1("NT headers beyond file size!\n");
	return STATUS_INVALID_IMAGE_FORMAT;
    }

    /* Now get a pointer to the NT Headers */
    PIMAGE_NT_HEADERS NtHeaders = NULL;
    Status = CcMapData(Fcb, *NtHeaderOffset, sizeof(IMAGE_NT_HEADERS),
		       NULL, (PVOID *)&NtHeaders);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    /* Verify the PE Signature */
    if (NtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        DPRINT1("Invalid image NT signature (expected 0x%x found 0x%x)\n",
		IMAGE_NT_SIGNATURE, NtHeaders->Signature);
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    /* Now return success and the NT header */
    *OutHeaders = NtHeaders;
    return STATUS_SUCCESS;
}

/*
 * Returns the file offset to the given data directory of the PE image file.
 * If needed, the size of the data directory is also returned.
 */
ULONG64 RtlImageDirectoryEntryToFileOffset(IN PIO_FILE_OBJECT FileObject,
					   IN USHORT Directory,
					   OUT OPTIONAL ULONG *Size)
{
    PIMAGE_NT_HEADERS NtHeader = RtlImageNtHeader(FileObject->Fcb);
    if (!NtHeader)
        return 0;

    if (Directory >= NtHeader->OptionalHeader.NumberOfRvaAndSizes)
        return 0;

    ULONG Rva = NtHeader->OptionalHeader.DataDirectory[Directory].VirtualAddress;
    if (!Rva)
        return 0;

    if (Size) {
	*Size = NtHeader->OptionalHeader.DataDirectory[Directory].Size;
    }

    return RtlImageRvaToFileOffset(FileObject, Rva);
}

/*
 * Return the SUBSECTION object corresponding to the given RVA.
 */
static PSUBSECTION RtlpImageRvaToSection(IN PIO_FILE_OBJECT FileObject,
					 IN ULONG Rva)
{
    PIO_FILE_CONTROL_BLOCK Fcb = FileObject->Fcb;
    assert(Fcb);
    PIMAGE_SECTION_OBJECT ImageSectionObject = Fcb->ImageSectionObject;
    assert(ImageSectionObject);
    LoopOverList(Section, &ImageSectionObject->SubSectionList, SUBSECTION, Link) {
        ULONG SectionRva = Section->SubSectionBase;
	ULONG SectionRvaEnd = SectionRva + Section->RawDataSize;
        if ((SectionRva <= Rva) && (Rva < SectionRvaEnd)) {
            return Section;
	}
    }
    return NULL;
}

/*
 * Return the file offset of the given RVA for the PE image file.
 */
ULONG64 RtlImageRvaToFileOffset(IN PIO_FILE_OBJECT FileObject,
				IN ULONG Rva)
{
    PSUBSECTION Section = RtlpImageRvaToSection(FileObject, Rva);
    if (!Section)
	return 0;

    /* PE files cannot be larger than 4GB so we don't need to worry about
     * integer overflow here. */
    assert(Rva >= Section->SubSectionBase);
    return Rva + Section->FileOffset - Section->SubSectionBase;
}
