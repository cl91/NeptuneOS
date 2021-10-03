#include <nt.h>
#include <debug.h>
#include <image.h>

NTSTATUS RtlpImageNtHeaderEx(IN ULONG Flags,
			     IN PVOID Base,
			     IN ULONG64 Size,
			     OUT PIMAGE_NT_HEADERS *OutHeaders)
{
    PIMAGE_NT_HEADERS NtHeaders;
    PIMAGE_DOS_HEADER DosHeader;
    BOOLEAN WantsRangeCheck;
    ULONG NtHeaderOffset;

    /* You must want NT Headers, no? */
    if (OutHeaders == NULL) {
        DPRINT1("OutHeaders is NULL\n");
        return STATUS_INVALID_PARAMETER;
    }

    /* Assume failure */
    *OutHeaders = NULL;

    /* Validate Flags */
    if (Flags & ~RTL_IMAGE_NT_HEADER_EX_FLAG_NO_RANGE_CHECK) {
        DPRINT1("Invalid flags: 0x%x\n", Flags);
        return STATUS_INVALID_PARAMETER;
    }

    /* Validate base */
    if ((Base == NULL) || (Base == (PVOID)-1)) {
        DPRINT1("Invalid base address: %p\n", Base);
        return STATUS_INVALID_PARAMETER;
    }

    /* Check if the caller wants range checks */
    WantsRangeCheck = !(Flags & RTL_IMAGE_NT_HEADER_EX_FLAG_NO_RANGE_CHECK);
    if (WantsRangeCheck) {
        /* Make sure the image size is at least big enough for the DOS header */
        if (Size < sizeof(IMAGE_DOS_HEADER)) {
            DPRINT1("File buffer size too small\n");
            return STATUS_INVALID_IMAGE_FORMAT;
        }
    }

    /* Check if the DOS Signature matches */
    DosHeader = Base;
    if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        /* Not a valid COFF */
        DPRINT1("Invalid image DOS signature (expected 0x%x found 0x%x)\n",
		IMAGE_DOS_SIGNATURE, DosHeader->e_magic);
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    if (DosHeader->e_lfanew <= 0) {
        DPRINT1("Not a Windows executable, e_lfanew is %d\n", DosHeader->e_lfanew);
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    /* Get the offset to the NT headers (and copy from LONG to ULONG) */
    NtHeaderOffset = DosHeader->e_lfanew;

    /* The offset must not be larger than 256MB, as a hard-coded check.
       In Windows this check is only done in user mode, not in kernel mode,
       but it shouldn't harm to have it anyway. Note that without this check,
       other overflow checks would become necessary! */
    if (NtHeaderOffset >= (256 * 1024 * 1024)) {
        /* Fail */
        DPRINT1("NT headers offset is larger than 256MB!\n");
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    /* Check if the caller wants validation */
    if (WantsRangeCheck) {
        /* Make sure the file header fits into the size */
        if ((NtHeaderOffset + RTL_SIZEOF_THROUGH_FIELD(IMAGE_NT_HEADERS, FileHeader)) >= Size) {
            /* Fail */
            DPRINT1("NT headers beyond file buffer size!\n");
            return STATUS_INVALID_IMAGE_FORMAT;
        }
    }

    /* Now get a pointer to the NT Headers */
    NtHeaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)Base + NtHeaderOffset);

    /* Verify the PE Signature */
    if (NtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        /* Fail */
        DPRINT1("Invalid image NT signature (expected 0x%x found 0x%x)\n",
		IMAGE_NT_SIGNATURE, NtHeaders->Signature);
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    /* Now return success and the NT header */
    *OutHeaders = NtHeaders;
    return STATUS_SUCCESS;
}

/*
 * @implemented
 */
PVOID NTAPI RtlImageDirectoryEntryToData(IN PVOID BaseAddress,
					 IN BOOLEAN MappedAsImage,
					 IN USHORT Directory,
					 IN PULONG Size)
{
    PIMAGE_NT_HEADERS NtHeader;
    ULONG Va;

    /* Magic flag for non-mapped images. */
    if ((ULONG_PTR)BaseAddress & 1) {
        BaseAddress = (PVOID)((ULONG_PTR)BaseAddress & ~1);
        MappedAsImage = FALSE;
    }

    NtHeader = RtlImageNtHeader(BaseAddress);
    if (NtHeader == NULL)
        return NULL;

    if (Directory >= SWAPD(NtHeader->OptionalHeader.NumberOfRvaAndSizes))
        return NULL;

    Va = SWAPD(NtHeader->OptionalHeader.DataDirectory[Directory].VirtualAddress);
    if (Va == 0)
        return NULL;

    *Size = SWAPD(NtHeader->OptionalHeader.DataDirectory[Directory].Size);

    if (MappedAsImage || Va < SWAPD(NtHeader->OptionalHeader.SizeOfHeaders))
        return (PVOID)((ULONG_PTR)BaseAddress + Va);

    /* Image mapped as ordinary file, we must find raw pointer */
    return RtlImageRvaToVa(NtHeader, BaseAddress, Va, NULL);
}

/*
 * @implemented
 */
PIMAGE_SECTION_HEADER NTAPI RtlImageRvaToSection(IN PIMAGE_NT_HEADERS NtHeader,
						 IN PVOID BaseAddress,
						 IN ULONG Rva)
{
    PIMAGE_SECTION_HEADER Section;
    ULONG Va;
    ULONG Count;

    Count = SWAPW(NtHeader->FileHeader.NumberOfSections);
    Section = IMAGE_FIRST_SECTION(NtHeader);

    while (Count--) {
        Va = SWAPD(Section->VirtualAddress);
        if ((Va <= Rva) && (Rva < Va + SWAPD(Section->SizeOfRawData))) {
            return Section;
	}
        Section++;
    }

    return NULL;
}

/*
 * @implemented
 */
PVOID NTAPI RtlImageRvaToVa(IN PIMAGE_NT_HEADERS NtHeader,
			    IN PVOID BaseAddress,
			    IN ULONG Rva,
			    IN PIMAGE_SECTION_HEADER *SectionHeader)
{
    PIMAGE_SECTION_HEADER Section = NULL;

    if (SectionHeader)
        Section = *SectionHeader;

    if ((Section == NULL) || (Rva < SWAPD(Section->VirtualAddress)) ||
        (Rva >= SWAPD(Section->VirtualAddress) + SWAPD(Section->SizeOfRawData))) {
        Section = RtlImageRvaToSection(NtHeader, BaseAddress, Rva);
        if (Section == NULL)
            return NULL;

        if (SectionHeader)
            *SectionHeader = Section;
    }

    return (PVOID)((ULONG_PTR)BaseAddress + Rva +
                   (ULONG_PTR)SWAPD(Section->PointerToRawData) -
                   (ULONG_PTR)SWAPD(Section->VirtualAddress));
}
