#include "mi.h"
#include "intsafe.h"

NTSTATUS MiSectionObjectCreateProc(IN POBJECT Object)
{
    PSECTION Section = (PSECTION) Object;
    MiAvlInitializeNode(&Section->BasedSectionNode, 0);
    Section->Flags.Word = 0;
    Section->ImageSectionObject = NULL;
    return STATUS_SUCCESS;
}

NTSTATUS MiSectionInitialization()
{
    OBJECT_TYPE_INITIALIZER TypeInfo = {
	.CreateProc = MiSectionObjectCreateProc,
	.OpenProc = NULL,
	.ParseProc = NULL,
	.InsertProc = NULL,
    };
    return ObCreateObjectType(OBJECT_TYPE_SECTION,
			      "Section",
			      sizeof(SECTION),
			      TypeInfo);
}

static inline VOID MiInitializeImageSection(IN PIMAGE_SECTION_OBJECT ImageSection,
					    IN PFILE_OBJECT File)
{
    memset(ImageSection, 0, sizeof(IMAGE_SECTION_OBJECT));
    InitializeListHead(&ImageSection->SubSectionList);
}

static inline VOID MiInitializeSubSection(IN PSUBSECTION SubSection,
					  IN PIMAGE_SECTION_OBJECT ImageSection)
{
    memset(SubSection, 0, sizeof(SUBSECTION));
    SubSection->ImageSection = ImageSection;
    InitializeListHead(&SubSection->Link);
}

/*
 * This is stolen shamelessly from the ReactOS source code.
 *
 * Parse the PE image headers and populate the given image section object,
 * including the SUBSECTIONS. The number of subsections equal the number of PE
 * sections of the image file, plus the zeroth subsection which is the PE image
 * headers.
 *
 * References:
 *  [1] Microsoft Corporation, "Microsoft Portable Executable and Common Object
 *      File Format Specification", revision 6.0 (February 1999)
 */
#define DIE(...) { DbgTrace(__VA_ARGS__); return Status; }
static NTSTATUS MiParseImageHeaders(IN PVOID FileBuffer,
				    IN ULONG FileBufferSize,
				    IN PIMAGE_SECTION_OBJECT ImageSection)
{
    assert(FileBuffer);
    assert(FileBufferSize);
    assert(ImageSection != NULL);
    assert(Intsafe_CanOffsetPointer(FileBuffer, FileBufferSize));

    /*
     * DOS HEADER
     */
    PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER) FileBuffer;
    NTSTATUS Status = STATUS_INVALID_IMAGE_NOT_MZ;
    /* Image too small to be an MZ executable */
    if (FileBufferSize < sizeof(IMAGE_DOS_HEADER)) {
        DIE("Too small to be an MZ executable, size is 0x%x\n", FileBufferSize);
    }
    /* No MZ signature */
    if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        DIE("No MZ signature found, e_magic is %hX\n", DosHeader->e_magic);
    }

    /*
     * NT HEADERS, which include COFF header and Optional header
     */
    Status = STATUS_INVALID_IMAGE_PROTECT;
    /* Not a Windows executable */
    if (DosHeader->e_lfanew <= 0) {
        DIE("Not a Windows executable, e_lfanew is %d\n", DosHeader->e_lfanew);
    }

    /* Make sure we have read the whole COFF header into memory. */
    ULONG OptHeaderOffset = 0;	/* File offset of optional header */
    if (!Intsafe_AddULong32(&OptHeaderOffset, DosHeader->e_lfanew,
			    RTL_SIZEOF_THROUGH_FIELD(IMAGE_NT_HEADERS, FileHeader))) {
        DIE("The DOS stub is too large, e_lfanew is %X\n", DosHeader->e_lfanew);
    }
    /* The buffer doesn't contain all of COFF headers: read it from the file */
    if (FileBufferSize < OptHeaderOffset) {
	return STATUS_NTOS_UNIMPLEMENTED;
    }

    /*
     * We already know that Intsafe_CanOffsetPointer(FileBuffer, FileBufferSize),
     * and FileBufferSize >= OptHeaderOffset, so this holds true too.
     */
    assert(Intsafe_CanOffsetPointer(FileBuffer, DosHeader->e_lfanew));
    PIMAGE_NT_HEADERS NtHeader = (PIMAGE_NT_HEADERS)
	((ULONG_PTR)FileBuffer + DosHeader->e_lfanew);

    /* Validate PE signature */
    Status = STATUS_INVALID_IMAGE_PROTECT;
    if (NtHeader->Signature != IMAGE_NT_SIGNATURE) {
	DIE("The file isn't a PE executable, Signature is %X\n", NtHeader->Signature);
    }

    Status = STATUS_INVALID_IMAGE_FORMAT;
    PIMAGE_OPTIONAL_HEADER OptHeader = &NtHeader->OptionalHeader;
    ULONG OptHeaderSize = NtHeader->FileHeader.SizeOfOptionalHeader;

    /* Make sure we have read the whole optional header into memory. */
    ULONG SectionHeadersOffset = 0; /* File offset of beginning of section header table */
    if (!Intsafe_AddULong32(&SectionHeadersOffset, OptHeaderOffset, OptHeaderSize)) {
	DIE("The NT header is too large, SizeOfOptionalHeader is %X\n", OptHeaderSize);
    }
    /* The buffer doesn't contain the full optional header: read it from the file */
    if (FileBufferSize < SectionHeadersOffset) {
	return STATUS_NTOS_UNIMPLEMENTED;
    }

    /* Read information from the optional header */
    Status = STATUS_INVALID_IMAGE_FORMAT;
    if (!RTL_CONTAINS_FIELD(OptHeader, OptHeaderSize, Magic)) {
        DIE("The optional header does not contain the Magic field,"
	    " SizeOfOptionalHeader is %X\n", OptHeaderSize);
    }

    /* We only process PE files that are native to the architecture, which for
     * i386 is PE32, and for amd64 is PE32+ */
    if (OptHeader->Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC) {
	DIE("Invalid optional header, Magic is %X\n", OptHeader->Magic);
    }

    /* Validate section alignment and file alignment */
    if (!RTL_CONTAINS_FIELD(OptHeader, OptHeaderSize, SectionAlignment) ||
	!RTL_CONTAINS_FIELD(OptHeader, OptHeaderSize, FileAlignment)) {
	DIE("Optional header does not contain section alignment or file alignment\n");
    }
    /* See [1], section 3.4.2 */
    if(OptHeader->SectionAlignment < PAGE_SIZE) {
	if(OptHeader->FileAlignment != OptHeader->SectionAlignment) {
	    DIE("Sections aren't page-aligned and the file alignment isn't the same\n");
	}
    } else if(OptHeader->SectionAlignment < OptHeader->FileAlignment) {
	DIE("The section alignment is smaller than the file alignment\n");
    }
    ULONG SectionAlignment = OptHeader->SectionAlignment;
    ULONG FileAlignment = OptHeader->FileAlignment;
    if (!IsPowerOf2(SectionAlignment) || !IsPowerOf2(FileAlignment)) {
	DIE("The section alignment (%u) and file alignment (%u)"
	    " must both be powers of two\n", SectionAlignment, FileAlignment);
    }
    if (SectionAlignment < PAGE_SIZE) {
	SectionAlignment = PAGE_SIZE;
    }

    /* Validate image base */
    if (!RTL_CONTAINS_FIELD(OptHeader, OptHeaderSize, ImageBase)) {
	DIE("Optional header does not contain ImageBase\n");
    }
    /* [1], section 3.4.2 */
    if (OptHeader->ImageBase % 0x10000) {
	DIE("ImageBase is not aligned on a 64KB boundary\n");
    }
    ImageSection->ImageBase = OptHeader->ImageBase;

    /* Populate image information of the image section object. */
    PSECTION_IMAGE_INFORMATION ImageInformation = &ImageSection->ImageInformation;
    if (RTL_CONTAINS_FIELD(OptHeader, OptHeaderSize, SizeOfImage)) {
	ImageInformation->ImageFileSize = OptHeader->SizeOfImage;
    }
    if (RTL_CONTAINS_FIELD(OptHeader, OptHeaderSize, SizeOfStackReserve)) {
	ImageInformation->MaximumStackSize = OptHeader->SizeOfStackReserve;
    }
    if (RTL_CONTAINS_FIELD(OptHeader, OptHeaderSize, SizeOfStackCommit)) {
	ImageInformation->CommittedStackSize = OptHeader->SizeOfStackCommit;
    }
    if (RTL_CONTAINS_FIELD(OptHeader, OptHeaderSize, Subsystem)) {
	ImageInformation->SubSystemType = OptHeader->Subsystem;
	if (RTL_CONTAINS_FIELD(OptHeader, OptHeaderSize, MinorSubsystemVersion) &&
	    RTL_CONTAINS_FIELD(OptHeader, OptHeaderSize, MajorSubsystemVersion)) {
	    ImageInformation->SubSystemMinorVersion = OptHeader->MinorSubsystemVersion;
	    ImageInformation->SubSystemMajorVersion = OptHeader->MajorSubsystemVersion;
	}
    }
    if (RTL_CONTAINS_FIELD(OptHeader, OptHeaderSize, AddressOfEntryPoint)) {
	ImageInformation->TransferAddress =
	    (PVOID) (OptHeader->ImageBase + OptHeader->AddressOfEntryPoint);
    }
    if (RTL_CONTAINS_FIELD(OptHeader, OptHeaderSize, SizeOfCode)) {
	ImageInformation->ImageContainsCode = (OptHeader->SizeOfCode != 0);
    } else {
	ImageInformation->ImageContainsCode = TRUE;
    }
    if (RTL_CONTAINS_FIELD(OptHeader, OptHeaderSize, AddressOfEntryPoint) &&
	(OptHeader->AddressOfEntryPoint == 0)) {
	ImageInformation->ImageContainsCode = FALSE;
    }
    if (RTL_CONTAINS_FIELD(OptHeader, OptHeaderSize, LoaderFlags)) {
	ImageInformation->LoaderFlags = OptHeader->LoaderFlags;
    }
    if (RTL_CONTAINS_FIELD(OptHeader, OptHeaderSize, DllCharacteristics)) {
	ImageInformation->DllCharacteristics = OptHeader->DllCharacteristics;
    }

    /*
     * Since we don't really implement SxS yet and LD doesn't support
     * /ALLOWISOLATION:NO, hard-code this flag here, which will prevent
     * the loader and other code from doing any .manifest or SxS magic
     * to any binary.
     *
     * This will break applications that depend on SxS when running with
     * real Windows Kernel32/SxS/etc but honestly that's not tested. It
     * will also break them when running on ReactOS once we implement
     * the SxS support -- at which point, duh, this should be removed.
     *
     * But right now, any app depending on SxS is already broken anyway,
     * so this flag only helps.
     */
    ImageInformation->DllCharacteristics |= IMAGE_DLLCHARACTERISTICS_NO_ISOLATION;

    ImageInformation->ImageCharacteristics = NtHeader->FileHeader.Characteristics;
    ImageInformation->Machine = NtHeader->FileHeader.Machine;
    ImageInformation->GpValue = 0;
    ImageInformation->ZeroBits = 0;

    /*
     * SECTION HEADERS
     */
    Status = STATUS_INVALID_IMAGE_FORMAT;
    /* See [1], section 3.3 */
    if (NtHeader->FileHeader.NumberOfSections > 96) {
        DIE("Too many sections, NumberOfSections is %u\n",
	    NtHeader->FileHeader.NumberOfSections);
    }

    /* Size of the executable's headers. This includes the DOS header and
     * NT headers (the COFF header and the optional header), as well as
     * the section tables. */
    if (!RTL_CONTAINS_FIELD(OptHeader, OptHeaderSize, SizeOfHeaders)) {
	DIE("Optional header does not contain SizeOfHeaders member\n");
    }
    ULONG AllHeadersSize = OptHeader->SizeOfHeaders;
    if (!IS_ALIGNED(AllHeadersSize, FileAlignment)) {
        DIE("SizeOfHeaders is not aligned with file alignment\n");
    }
    assert(Intsafe_CanMulULong32(NtHeader->FileHeader.NumberOfSections,
				 sizeof(IMAGE_SECTION_HEADER)));
    if (AllHeadersSize <
	NtHeader->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER)) {
	DIE("SizeOfHeaders is less than number of sections times section header size\n");
    }
    /* Make sure we have read the entire section header table into memory. */
    if (FileBufferSize < AllHeadersSize) {
	return STATUS_NTOS_UNIMPLEMENTED;
    }

    /*
     * We already know that Intsafe_CanOffsetPointer(FileBuffer, FileBufferSize),
     * and FileBufferSize >= FirstSectionOffset, so this holds true too.
     */
    assert(Intsafe_CanOffsetPointer(FileBuffer, SectionHeadersOffset));
    PIMAGE_SECTION_HEADER SectionHeaders = (PIMAGE_SECTION_HEADER)
	((ULONG_PTR)FileBuffer + SectionHeadersOffset);

    /*
     * Parse the section tables and validate their values before we start
     * building SUBSECTIONS for the image section.
     *
     * See [1], section 4
     */
    Status = STATUS_INVALID_IMAGE_FORMAT;
    MWORD PreviousSectionEnd = ALIGN_UP_BY(AllHeadersSize, SectionAlignment);
    for (ULONG i = 0; i < NtHeader->FileHeader.NumberOfSections; i++) {
        ULONG Characteristics;

        /* Validate alignment */
        if (!IS_ALIGNED(SectionHeaders[i].VirtualAddress, SectionAlignment)) {
            DIE("Section %u VirtualAddress is not aligned\n", i);
	}

        /* Sections must be contiguous, ordered by base address and non-overlapping */
        if(SectionHeaders[i].VirtualAddress != PreviousSectionEnd)
            DIE("Memory gap between section %u and the previous\n", i);

        /* Ignore explicit BSS sections */
        if (SectionHeaders[i].SizeOfRawData != 0) {
#if 0
            /* Yes, this should be a multiple of FileAlignment, but there's
             * stuff out there that isn't. We can cope with that
             */
            if (!IS_ALIGNED(SectionHeaders[i].SizeOfRawData, FileAlignment)) {
                DIE("SizeOfRawData[%u] is not aligned\n", i);
	    }
            if (!IS_ALIGNED(SectionHeaders[i].PointerToRawData, FileAlignment)) {
                DIE("PointerToRawData[%u] is not aligned\n", i);
	    }
#endif
            if (!Intsafe_CanAddULong32(SectionHeaders[i].PointerToRawData,
				       SectionHeaders[i].SizeOfRawData)) {
                DIE("SizeOfRawData[%u] too large\n", i);
	    }
	}

	MWORD VirtualSize = SectionHeaders[i].Misc.VirtualSize;
	if (VirtualSize == 0) {
            VirtualSize = SectionHeaders[i].SizeOfRawData;
	}
	if (VirtualSize == 0) {
            DIE("Virtual size of section %d is null\n", i);
	}

        /* Ensure the memory image is no larger than 4GB */
	VirtualSize = ALIGN_UP_BY(VirtualSize, SectionAlignment);
        if (PreviousSectionEnd + VirtualSize < PreviousSectionEnd) {
            DIE("The image is too large\n");
	}
	PreviousSectionEnd += VirtualSize;
    }

    /*
     * Parse the section headers and allocate SUBSECTIONS for the image section object.
     */
    Status = STATUS_INSUFFICIENT_RESOURCES;
    /* One additional subsection for the image headers. */
    LONG NumSubSections = NtHeader->FileHeader.NumberOfSections + 1;
    MiAllocateArray(SubSectionsArray, PSUBSECTION, NumSubSections, {});
    for (LONG i = 0; i < NumSubSections; i++) {
	MiAllocatePoolEx(SubSection, SUBSECTION,
			 {
			     for (LONG j = 0; j < i; j++) {
				 if (SubSectionsArray[j] == NULL) {
				     return STATUS_NTOS_BUG;
				 }
				 ExFreePool(SubSectionsArray[j]);
			     }
			     ExFreePool(SubSectionsArray);
			 });
	MiInitializeSubSection(SubSection, ImageSection);
	SubSectionsArray[i] = SubSection;
    }
    ImageSection->NumSubSections = NumSubSections;

    /* The zeroth subsection of the image section is the image headers */
    SubSectionsArray[0]->SubSectionSize = ALIGN_UP_BY(AllHeadersSize, SectionAlignment);
    SubSectionsArray[0]->FileOffset = 0;
    SubSectionsArray[0]->RawDataSize = AllHeadersSize;
    SubSectionsArray[0]->SubSectionBase = 0;
    SubSectionsArray[0]->Characteristics = 0;
    InsertTailList(&ImageSection->SubSectionList, &SubSectionsArray[0]->Link);

    for (LONG i = 1; i < NumSubSections; i++) {
	SubSectionsArray[i]->RawDataSize = SectionHeaders[i-1].SizeOfRawData;
	SubSectionsArray[i]->FileOffset = SectionHeaders[i-1].PointerToRawData;

        ULONG Characteristics = SectionHeaders[i-1].Characteristics;
        /* Image has no explicit protection. */
        if ((Characteristics & (IMAGE_SCN_MEM_EXECUTE |
				IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE)) == 0) {
            if (Characteristics & IMAGE_SCN_CNT_CODE) {
                Characteristics |= IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
	    }
            if (Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) {
                Characteristics |= IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
	    }
            if (Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) {
                Characteristics |= IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
	    }
        }
	SubSectionsArray[i]->Characteristics = Characteristics;

	ULONG VirtualSize = SectionHeaders[i-1].Misc.VirtualSize;
	if (VirtualSize == 0) {
            VirtualSize = SectionHeaders[i-1].SizeOfRawData;
	}
	VirtualSize = ALIGN_UP_BY(VirtualSize, SectionAlignment);

        SubSectionsArray[i]->SubSectionSize = VirtualSize;
        SubSectionsArray[i]->SubSectionBase = SectionHeaders[i-1].VirtualAddress;

	InsertTailList(&ImageSection->SubSectionList, &SubSectionsArray[i]->Link);
    }

    ExFreePool(SubSectionsArray);
    return STATUS_SUCCESS;
}
#undef DIE

static NTSTATUS MiCreateImageFileMap(IN PFILE_OBJECT File,
				     OUT PIMAGE_SECTION_OBJECT *pImageSection)
{
    assert(File != NULL);
    assert(pImageSection != NULL);
    MiAllocatePool(ImageSection, IMAGE_SECTION_OBJECT);
    MiInitializeImageSection(ImageSection, File);

    RET_ERR_EX(MiParseImageHeaders((PVOID) File->BufferPtr, File->Size, ImageSection),
	       ExFreePool(ImageSection));

    File->SectionObject.ImageSectionObject = ImageSection;
    *pImageSection = ImageSection;
    return STATUS_SUCCESS;
}

NTSTATUS MmCreateSection(IN PFILE_OBJECT FileObject,
			 IN MWORD Attribute,
			 OUT PSECTION *SectionObject)
{
    assert(FileObject != NULL);
    assert(SectionObject != NULL);
    *SectionObject = NULL;

    /* Only image section is implemented for now */
    if (!(Attribute & SEC_IMAGE)) {
	return STATUS_NTOS_UNIMPLEMENTED;
    }

    if (!(Attribute & SEC_RESERVE)) {
	return STATUS_NTOS_UNIMPLEMENTED;
    }

    if (!(Attribute & SEC_COMMIT)) {
	return STATUS_NTOS_UNIMPLEMENTED;
    }

    PIMAGE_SECTION_OBJECT ImageSection = FileObject->SectionObject.ImageSectionObject;

    if (ImageSection == NULL) {
	RET_ERR(MiCreateImageFileMap(FileObject, &ImageSection));
	assert(ImageSection != NULL);
    }

    PSECTION Section = NULL;
    RET_ERR(ObCreateObject(OBJECT_TYPE_SECTION, (POBJECT *) &Section));
    assert(Section != NULL);
    Section->Flags.File = 1;
    Section->Flags.Image = 1;
    /* For now all sections are committed immediately. */
    Section->Flags.Reserve = 1;
    Section->Flags.Commit = 1;
    Section->ImageSectionObject = ImageSection;

    *SectionObject = Section;
    return STATUS_SUCCESS;
}

static NTSTATUS MiMapViewOfImageSection(IN PVIRT_ADDR_SPACE VSpace,
					IN PSECTION Section,
					IN OUT MWORD *BaseAddress,
					IN OUT MWORD *SectionOffset,
					IN OUT MWORD *ViewSize)
{
    return STATUS_SUCCESS;
}

/*
 * Map a view of the given section onto the given virtual address space.
 *
 * For now we commit the full view (CommitSize == ViewSize).
 */
NTSTATUS MmMapViewOfSection(IN PVIRT_ADDR_SPACE VSpace,
			    IN PSECTION Section,
			    IN OUT MWORD *BaseAddress,
			    IN OUT MWORD *SectionOffset,
			    IN OUT MWORD *ViewSize)
{
    assert(VSpace != NULL);
    assert(Section != NULL);
    if (Section->Flags.Image) {
	return MiMapViewOfImageSection(VSpace, Section, BaseAddress,
				       SectionOffset, ViewSize);
    }
    return STATUS_NTOS_UNIMPLEMENTED;
}