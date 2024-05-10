#include "mi.h"
#include "intsafe.h"

PSECTION MiPhysicalSection;

/*
 * Note: we assume memset(ImageSection, 0, sizeof(IMAGE_SECTION_OBJECT)) has
 * been called before this routine is called.
 */
static inline VOID MiInitializeImageSection(IN PIMAGE_SECTION_OBJECT ImageSection,
					    IN PIO_FILE_OBJECT File)
{
    InitializeListHead(&ImageSection->SubSectionList);
}

/*
 * Note: we assume memset(Subsection, 0, sizeof(SUBSECTION)) has been called
 * before this routine is called.
 */
static inline VOID MiInitializeSubSection(IN PSUBSECTION SubSection,
					  IN PIMAGE_SECTION_OBJECT ImageSection)
{
    SubSection->ImageSection = ImageSection;
    InitializeListHead(&SubSection->Link);
}

/*
 * Parse the PE image headers and populate the given image section object,
 * including the SUBSECTIONs. The number of subsections equals the number of PE
 * sections of the image file plus the zeroth subsection which is the PE image
 * headers. The shared cache map of the file object must be pinned and populated
 * before calling this routine.
 *
 * References:
 *  [1] Microsoft Corporation, "Microsoft Portable Executable and Common Object
 *      File Format Specification", revision 6.0 (February 1999)
 */
#define DIE(...) { MmDbg(__VA_ARGS__); return STATUS_INVALID_IMAGE_FORMAT; }
static NTSTATUS MiParseImageHeaders(IN PIO_FILE_OBJECT FileObject,
				    IN PIMAGE_SECTION_OBJECT ImageSection,
				    OUT MWORD *pSectionSize)
{
    assert(FileObject);
    assert(FileObject->Fcb);
    assert(FileObject->Fcb->SharedCacheMap);
    assert(ImageSection);
    assert(pSectionSize);

    PIMAGE_NT_HEADERS NtHeader = NULL;
    ULONG64 NtHeaderOffset = 0;
    RET_ERR(RtlImageNtHeaderEx(FileObject->Fcb, &NtHeader, &NtHeaderOffset));
    assert(NtHeader);
    assert(NtHeaderOffset);

    ULONG OptHeaderSize = NtHeader->FileHeader.SizeOfOptionalHeader;
    ULONG64 OptHeaderOffset = NtHeaderOffset + FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader);
    PIMAGE_OPTIONAL_HEADER OptHeader = NULL;
    RET_ERR(CcMapData(FileObject->Fcb, OptHeaderOffset, OptHeaderSize,
		      NULL, (PVOID *)&OptHeader));

    /* Make sure the optional header size is big enough */
    if (!RTL_CONTAINS_FIELD(OptHeader, OptHeaderSize, NumberOfRvaAndSizes)) {
        DIE("SizeOfOptionalHeader 0x%x too small\n", OptHeaderSize);
    }

    /* We only process PE files that are native to the architecture, which for
     * i386 is PE32, and for amd64 is PE32+ */
    if (OptHeader->Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC) {
	DIE("Invalid optional header, magic is 0x%x\n", OptHeader->Magic);
    }

    /* Validate section alignment and file alignment. See [1], section 3.4.2 */
    if (OptHeader->SectionAlignment < PAGE_SIZE) {
	if (OptHeader->FileAlignment != OptHeader->SectionAlignment) {
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

    /* Validate image base. See [1], section 3.4.2 */
    if (OptHeader->ImageBase % 0x10000) {
	DIE("ImageBase is not aligned on a 64KB boundary\n");
    }
    ImageSection->ImageBase = OptHeader->ImageBase;

    /* Populate image information of the image section object. */
    PSECTION_IMAGE_INFORMATION ImageInformation = &ImageSection->ImageInformation;
    ImageInformation->ImageFileSize = OptHeader->SizeOfImage;
    ImageInformation->MaximumStackSize = OptHeader->SizeOfStackReserve;
    ImageInformation->CommittedStackSize = OptHeader->SizeOfStackCommit;
    ImageInformation->SubSystemType = OptHeader->Subsystem;
    ImageInformation->SubSystemMinorVersion = OptHeader->MinorSubsystemVersion;
    ImageInformation->SubSystemMajorVersion = OptHeader->MajorSubsystemVersion;
    ImageInformation->TransferAddress =
	(PVOID)(OptHeader->ImageBase + OptHeader->AddressOfEntryPoint);
    ImageInformation->ImageContainsCode =
	OptHeader->SizeOfCode && OptHeader->AddressOfEntryPoint;
    ImageInformation->LoaderFlags = OptHeader->LoaderFlags;
    ImageInformation->DllCharacteristics = OptHeader->DllCharacteristics;

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

    /* Size of the executable's headers. This includes the DOS header and
     * NT headers (the COFF header and the optional header), as well as
     * the section tables. */
    ULONG AllHeadersSize = OptHeader->SizeOfHeaders;
    if (!IS_ALIGNED_BY(AllHeadersSize, FileAlignment)) {
        DIE("SizeOfHeaders is not aligned with file alignment\n");
    }

    /*
     * SECTION HEADERS
     * See [1], section 3.3
     */
    ULONG NumberOfSections = NtHeader->FileHeader.NumberOfSections;
    if (!NumberOfSections) {
	DIE("Image must have at least one section.\n");
    }
    assert(Intsafe_CanMulULong32(NumberOfSections, sizeof(IMAGE_SECTION_HEADER)));
    ULONG SectionHeadersSize = NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
    if (AllHeadersSize < SectionHeadersSize) {
	DIE("SizeOfHeaders is less than number of sections times section header size\n");
    }

    /* The table of section headers is immediately after the optional header. */
    ULONG64 SectionHeadersOffset = OptHeaderOffset + OptHeaderSize;
    PIMAGE_SECTION_HEADER SectionHeaders = NULL;
    RET_ERR(CcMapData(FileObject->Fcb, SectionHeadersOffset, SectionHeadersSize,
		      NULL, (PVOID *)&SectionHeaders));
    assert(SectionHeaders);

    /*
     * Parse the section tables and validate their values before we start
     * building SUBSECTIONS for the image section.
     *
     * See [1], section 4
     */
    MWORD PreviousSectionEnd = ALIGN_UP_BY(AllHeadersSize, SectionAlignment);
    for (ULONG i = 0; i < NumberOfSections; i++) {
        /* Validate alignment */
        if (!IS_ALIGNED_BY(SectionHeaders[i].VirtualAddress, SectionAlignment)) {
            DIE("Section %u VirtualAddress is not aligned\n", i);
	}

        /* Sections must be contiguous, ordered by base address and non-overlapping */
        if(SectionHeaders[i].VirtualAddress != PreviousSectionEnd)
            DIE("Memory gap between section %u and the previous\n", i);

	/* Validate SizeOfRawData */
        if (SectionHeaders[i].SizeOfRawData &&
	    !Intsafe_CanAddULong32(SectionHeaders[i].PointerToRawData,
				   SectionHeaders[i].SizeOfRawData)) {
	    DIE("SizeOfRawData[%u] too large\n", i);
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
     * One additional subsection (the zeroth subsection) is for the image headers.
     */
    LONG NumSubSections = NumberOfSections + 1;
    MiAllocateArray(SubSectionsArray, PSUBSECTION, NumSubSections, {});
    for (LONG i = 0; i < NumSubSections; i++) {
	MiAllocatePoolEx(SubSection, SUBSECTION,
			 {
			     for (LONG j = 0; j < i; j++) {
				 assert(SubSectionsArray[j]);
				 MiFreePool(SubSectionsArray[j]);
			     }
			     MiFreePool(SubSectionsArray);
			 });
	MiInitializeSubSection(SubSection, ImageSection);
	SubSectionsArray[i] = SubSection;
    }
    ImageSection->NumSubSections = NumSubSections;

    /* The zeroth subsection of the image section is the image headers */
    SubSectionsArray[0]->SubSectionSize = ALIGN_UP_BY(AllHeadersSize, SectionAlignment);
    memcpy(SubSectionsArray[0]->Name, "PEIMGHDR", IMAGE_SIZEOF_SHORT_NAME);
    SubSectionsArray[0]->Name[IMAGE_SIZEOF_SHORT_NAME] = '\0';
    SubSectionsArray[0]->FileOffset = 0;
    SubSectionsArray[0]->RawDataSize = AllHeadersSize;
    SubSectionsArray[0]->SubSectionBase = 0;
    SubSectionsArray[0]->Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;
    InsertTailList(&ImageSection->SubSectionList, &SubSectionsArray[0]->Link);
    MWORD SectionSize = SubSectionsArray[0]->SubSectionSize;
    ULONG ImageCacheFileSize = SectionSize;

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
	assert(SubSectionsArray[i-1]->SubSectionBase + SubSectionsArray[i-1]->SubSectionSize
	       == SubSectionsArray[i]->SubSectionBase);
	memcpy(SubSectionsArray[i]->Name, SectionHeaders[i-1].Name, IMAGE_SIZEOF_SHORT_NAME);
	SubSectionsArray[i]->Name[IMAGE_SIZEOF_SHORT_NAME] = '\0';

	/* If the section contains code or initialized data, we add it to the
	 * image cache file. */
	if (Characteristics & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_CNT_INITIALIZED_DATA)) {
	    SubSectionsArray[i]->ImageCacheFileOffset = ImageCacheFileSize;
	    ImageCacheFileSize += VirtualSize;
	} else {
	    SubSectionsArray[i]->ImageCacheFileOffset = ULONG_MAX;
	}
	SectionSize += VirtualSize;

	InsertTailList(&ImageSection->SubSectionList, &SubSectionsArray[i]->Link);
    }
    ImageSection->ImageCacheFileSize = ImageCacheFileSize;

    MiFreePool(SubSectionsArray);
    *pSectionSize = SectionSize;
    return STATUS_SUCCESS;
}
#undef DIE

static VOID MiImageSectionPinDataCallback(IN PIO_FILE_CONTROL_BLOCK Fcb,
					  IN ULONG64 FileOffset,
					  IN ULONG64 Length,
					  IN NTSTATUS Status,
					  IN OUT PVOID Context)
{
    PNTSTATUS pStatus = Context;
    *pStatus = Status;
}

static NTSTATUS MiCreateImageFileMap(IN PIO_FILE_OBJECT File,
				     OUT PIMAGE_SECTION_OBJECT *pImageSection,
				     OUT MWORD *pSectionSize)
{
    assert(File);
    assert(File->Fcb);
    assert(pImageSection);
    MiAllocatePool(ImageSection, IMAGE_SECTION_OBJECT);
    MiInitializeImageSection(ImageSection, File);

    NTSTATUS Status;
    PIO_FILE_OBJECT ImageCacheFile = NULL;
    IF_ERR_GOTO(out, Status, MiParseImageHeaders(File, ImageSection, pSectionSize));
    IF_ERR_GOTO(out, Status, IoCreateDevicelessFile(NULL, NULL,
						    ImageSection->ImageCacheFileSize,
						    0, &ImageCacheFile));
    assert(ImageCacheFile->Fcb);
    IF_ERR_GOTO(out, Status, CcInitializeCacheMap(ImageCacheFile->Fcb, NULL, NULL));
    CcPinDataEx(ImageCacheFile->Fcb, 0, ImageSection->ImageCacheFileSize, FALSE,
		MiImageSectionPinDataCallback, &Status);
    if (!NT_SUCCESS(Status)) {
	goto out;
    }
    LoopOverList(SubSection, &ImageSection->SubSectionList, SUBSECTION, Link) {
	if (SubSection->ImageCacheFileOffset == ULONG_MAX) {
	    continue;
	}
	ULONG BytesCopied = 0;
	while (BytesCopied < SubSection->RawDataSize) {
	    ULONG MappedLength;
	    PVOID Buffer;
	    IF_ERR_GOTO(out, Status, CcMapData(ImageCacheFile->Fcb,
					       SubSection->ImageCacheFileOffset + BytesCopied,
					       SubSection->RawDataSize - BytesCopied,
					       &MappedLength, &Buffer));
	    IF_ERR_GOTO(out, Status, CcCopyRead(File->Fcb,
						SubSection->FileOffset + BytesCopied,
						MappedLength, Buffer));
	    BytesCopied += MappedLength;
	}
    }

    assert(File->Fcb);
    assert(File->Fcb->MasterFileObject);
    ObpReferenceObject(File->Fcb->MasterFileObject);
    File->Fcb->ImageSectionObject = ImageSection;
    ImageSection->Fcb = File->Fcb;
    ImageSection->ImageCacheFile = ImageCacheFile;
    *pImageSection = ImageSection;
    Status = STATUS_SUCCESS;
out:
    if (!NT_SUCCESS(Status)) {
	if (ImageSection) {
	    MiFreePool(ImageSection);
	}
	if (ImageCacheFile) {
	    ObDereferenceObject(ImageCacheFile);
	}
    }
    return Status;
}

static NTSTATUS MiSectionObjectCreateProc(IN POBJECT Object,
					  IN PVOID CreaCtx)
{
    PSECTION Section = (PSECTION) Object;
    PSECTION_OBJ_CREATE_CONTEXT Ctx = (PSECTION_OBJ_CREATE_CONTEXT)CreaCtx;
    PIO_FILE_OBJECT FileObject = Ctx->FileObject;
    ULONG Attributes = Ctx->Attributes;
    BOOLEAN PhysicalMapping = Ctx->PhysicalMapping;

    AvlInitializeNode(&Section->BasedSectionNode, 0);
    InitializeListHead(&Section->VadList);
    Section->Attributes = Attributes;

    if (PhysicalMapping) {
	Section->Flags.PhysicalMemory = 1;
	/* Physical section is always committed immediately. */
	Section->Flags.Reserve = 1;
	Section->Flags.Commit = 1;
	return STATUS_SUCCESS;
    }

    /* Only image section is implemented for now */
    if (!(Attributes & SEC_IMAGE)) {
	UNIMPLEMENTED;
    }

    assert(FileObject->Fcb);
    PIMAGE_SECTION_OBJECT ImageSection = FileObject->Fcb->ImageSectionObject;

    if (ImageSection == NULL) {
	RET_ERR(MiCreateImageFileMap(FileObject, &ImageSection, &Section->Size));
	assert(ImageSection != NULL);
    }

    Section->Flags.Image = 1;
    /* Image sections are always committed immediately. */
    Section->Flags.Reserve = 1;
    Section->Flags.Commit = 1;
    Section->ImageSectionObject = ImageSection;

    return STATUS_SUCCESS;
}

static VOID MiSectionObjectDeleteProc(IN POBJECT Self)
{
    assert(ObObjectIsType(Self, OBJECT_TYPE_SECTION));
    PSECTION Section = (PSECTION)Self;
    MmDbg("Deleting section object %p\n", Section);
    MmDbgDumpSection(Section);
    /* Unmap all the mapped view of this section */
    LoopOverList(Vad, &Section->VadList, MMVAD, SectionLink) {
	MmDeleteVad(Vad);
    }
    if (Section->Flags.Image && Section->ImageSectionObject) {
	if (Section->ImageSectionObject->ImageCacheFile) {
	    ObDereferenceObject(Section->ImageSectionObject->ImageCacheFile);
	}
	PIO_FILE_CONTROL_BLOCK Fcb = Section->ImageSectionObject->Fcb;
	if (Fcb) {
	    assert(Fcb->ImageSectionObject == Section->ImageSectionObject);
	    Fcb->ImageSectionObject = NULL;
	    if (Fcb->MasterFileObject) {
		ObDereferenceObject(Fcb->MasterFileObject);
	    }
	}
	MiFreePool(Section->ImageSectionObject);
    } else if (Section->Flags.File) {
	/* TODO! */
	assert(FALSE);
    }
}

NTSTATUS MmSectionInitialization()
{
    OBJECT_TYPE_INITIALIZER TypeInfo = {
	.CreateProc = MiSectionObjectCreateProc,
	.ParseProc = NULL,
	.OpenProc = NULL,
	.CloseProc = NULL,
	.InsertProc = NULL,
	.RemoveProc = NULL,
	.DeleteProc = MiSectionObjectDeleteProc
    };
    RET_ERR(ObCreateObjectType(OBJECT_TYPE_SECTION,
			       "Section",
			       sizeof(SECTION),
			       TypeInfo));

    /* Create VADs for "hyperspace", which is used for mapping client process
     * pages in the NTOS root task temporarily. The necessary super-structures
     * at starting addresses for 4K page hyperspace and large page hyperspace
     * will be mapped on-demand. */
    RET_ERR(MmReserveVirtualMemory(HYPERSPACE_4K_PAGE_START, 0, LARGE_PAGE_SIZE,
				   0, MEM_RESERVE_MIRRORED_MEMORY, NULL));
    RET_ERR(MmReserveVirtualMemory(HYPERSPACE_LARGE_PAGE_START, 0, LARGE_PAGE_SIZE,
				   0, MEM_RESERVE_MIRRORED_MEMORY, NULL));

    /* Create the singleton physical section. */
    SECTION_OBJ_CREATE_CONTEXT Ctx = {
	.PhysicalMapping = TRUE
    };
    RET_ERR(ObCreateObject(OBJECT_TYPE_SECTION, (POBJECT *)&MiPhysicalSection, &Ctx));
    assert(MiPhysicalSection != NULL);

    return STATUS_SUCCESS;
}

NTSTATUS MmCreateSection(IN PIO_FILE_OBJECT FileObject,
			 IN ULONG PageProtection,
			 IN ULONG SectionAttributes,
			 OUT PSECTION *SectionObject)
{
    assert(SectionObject != NULL);
    *SectionObject = NULL;

    PSECTION Section = NULL;
    SECTION_OBJ_CREATE_CONTEXT CreaCtx = {
	.FileObject = FileObject,
	.PageProtection = PageProtection,
	.Attributes = SectionAttributes
    };
    RET_ERR(ObCreateObject(OBJECT_TYPE_SECTION, (POBJECT *)&Section, &CreaCtx));
    assert(Section != NULL);

    *SectionObject = Section;
    return STATUS_SUCCESS;
}

NTSTATUS MmCreateSectionEx(IN ASYNC_STATE State,
			   IN PTHREAD Thread,
			   IN PIO_FILE_OBJECT FileObject,
			   IN ULONG PageProtection,
			   IN ULONG SectionAttributes,
			   OUT PSECTION *SectionObject)
{
    NTSTATUS Status = STATUS_SUCCESS;

    ASYNC_BEGIN(State);

    /* You cannot create a section object for a non-file-system file object. */
    if (FileObject && !FileObject->Fcb) {
	ASYNC_RETURN(State, STATUS_INVALID_PARAMETER);
    }

    /* For image section creation, we need to load the image file from disk
     * before calling MmCreateSection, because it needs to read the PE headers
     * to create the image section. */
    AWAIT_EX_IF(FileObject && (SectionAttributes & SEC_IMAGE), Status, CcPinData,
		State, _, Thread, FileObject->Fcb, 0, FileObject->Fcb->FileSize);
    if (!NT_SUCCESS(Status)) {
	ASYNC_RETURN(State, Status);
    }

    Status = MmCreateSection(FileObject, PageProtection,
			     SectionAttributes, SectionObject);

    if (FileObject && (SectionAttributes & SEC_IMAGE)) {
	CcUnpinData(FileObject->Fcb, 0, FileObject->Fcb->FileSize);
    }

    ASYNC_END(State, Status);
}

static NTSTATUS MiCommitImageVad(IN PMMVAD Vad)
{
    assert(Vad);
    assert(Vad->VSpace);
    assert(Vad->Flags.ImageMap);
    assert(IS_PAGE_ALIGNED(Vad->AvlNode.Key));
    assert(IS_PAGE_ALIGNED(Vad->WindowSize));
    assert(Vad->AvlNode.Key + Vad->WindowSize > Vad->AvlNode.Key);
    PSUBSECTION SubSection = Vad->ImageSectionView.SubSection;
    assert(SubSection);
    assert(SubSection->ImageSection);
    assert(SubSection->ImageSection->ImageCacheFile);

    PAGING_RIGHTS Rights = Vad->Flags.ReadOnly ? MM_RIGHTS_RO : MM_RIGHTS_RW;
    if (SubSection->RawDataSize) {
	ULONG BytesMapped = 0;
	while (BytesMapped < SubSection->SubSectionSize) {
	    ULONG MappedLength = 0;
	    PVOID Buffer = NULL;
	    RET_ERR(CcMapData(SubSection->ImageSection->ImageCacheFile->Fcb,
			      SubSection->ImageCacheFileOffset + BytesMapped,
			      SubSection->SubSectionSize - BytesMapped,
			      &MappedLength, &Buffer));
	    assert(MappedLength);
	    assert(Buffer);
	    assert(IS_PAGE_ALIGNED(MappedLength));
	    assert(IS_PAGE_ALIGNED(BytesMapped));
	    if (Vad->Flags.ReadOnly) {
		RET_ERR(MmMapMirroredMemory(&MiNtosVaddrSpace, (MWORD)Buffer,
					    Vad->VSpace, Vad->AvlNode.Key + BytesMapped,
					    MappedLength, Rights));
	    } else {
		RET_ERR(MmCommitOwnedMemoryEx(Vad->VSpace,
					      Vad->AvlNode.Key + BytesMapped,
					      MappedLength, Rights, FALSE,
					      Buffer, MappedLength));
	    }
	    BytesMapped += MappedLength;
	}
    } else {
	RET_ERR(MmCommitOwnedMemoryEx(Vad->VSpace, Vad->AvlNode.Key,
				      Vad->WindowSize, Rights,
				      Vad->Flags.LargePages, NULL, 0));
    }

    return STATUS_SUCCESS;
}

static NTSTATUS MiMapViewOfImageSection(IN PVIRT_ADDR_SPACE VSpace,
					IN PLIST_ENTRY SectionVadList,
					IN PIMAGE_SECTION_OBJECT ImageSection,
					IN OUT OPTIONAL MWORD *pBaseAddress,
					OUT OPTIONAL MWORD *pImageVirtualSize,
					IN ULONG HighZeroBits,
					IN ULONG ReserveFlags,
					IN BOOLEAN AlwaysWritable)
{
    assert(VSpace != NULL);
    assert(ImageSection != NULL);

    if (ReserveFlags & !(MEM_RESERVE_TOP_DOWN | MEM_RESERVE_LARGE_PAGES)) {
	return STATUS_INVALID_PARAMETER;
    }

    /* Compute the total in-memory size of the image */
    MWORD ImageVirtualSize = 0;
    LoopOverList(SubSection, &ImageSection->SubSectionList, SUBSECTION, Link) {
	ImageVirtualSize += SubSection->SubSectionSize;
    }

    /* Find an unused address window of ImageVirtualSize. If the user supplied the
     * base address, always map there. If not, try the preferred ImageBase specified
     * in the image file first */
    ULONG TopDownFlag = ReserveFlags & MEM_RESERVE_TOP_DOWN;
    MWORD BaseAddress = ImageSection->ImageBase;
    if ((pBaseAddress != NULL) && (*pBaseAddress != 0)) {
	BaseAddress = *pBaseAddress;
    } else if (!NT_SUCCESS(MmReserveVirtualMemoryEx(VSpace, BaseAddress, 0,
						    ImageVirtualSize, 0, HighZeroBits,
						    MEM_RESERVE_NO_INSERT | TopDownFlag,
						    NULL))) {
	/* We cannot map on the preferred image base. Search from the beginning
	 * of the user address space. */
	PMMVAD ImageVad = NULL;
	RET_ERR(MmReserveVirtualMemoryEx(VSpace, USER_IMAGE_REGION_START,
					 USER_IMAGE_REGION_END,
					 ImageVirtualSize, 0, HighZeroBits,
					 MEM_RESERVE_NO_INSERT | TopDownFlag,
					 &ImageVad));
	assert(ImageVad != NULL);
	BaseAddress = ImageVad->AvlNode.Key;
	assert(BaseAddress >= USER_IMAGE_REGION_START);
	assert(BaseAddress < USER_IMAGE_REGION_END);
	/* Since we have specified MEM_RESERVE_NO_INSERT above we can simply
	 * free the pool memory of ImageVad here. Calling MmDeleteVad would
	 * be incorrect here as the VAD has never been inserted. */
	MiFreePool(ImageVad);
    }

    NTSTATUS Status = STATUS_NTOS_BUG;
    /* We create a list to keep track of all the VADs for the subsections,
     * such that when mapping failed (say due to out of memory or cap slot)
     * we can clean up correctly. */
    LIST_ENTRY VadList;
    InitializeListHead(&VadList);
    /* For each subsection of the image section object, create a VAD that points
     * to the subsection, and commit the memory pages of that subsection. */
    LoopOverList(SubSection, &ImageSection->SubSectionList, SUBSECTION, Link) {
	PMMVAD Vad = NULL;
	BOOLEAN ReadOnly = !AlwaysWritable &&
	    !(SubSection->Characteristics & IMAGE_SCN_MEM_WRITE);
	MWORD Flags = MEM_RESERVE_IMAGE_MAP;
	if (ReadOnly) {
	    Flags |= MEM_RESERVE_READ_ONLY;
	}
	/* If the caller specified it and PE bss section is large enough,
	 * use large pages to save resources */
	if ((ReserveFlags & MEM_RESERVE_LARGE_PAGES) && !SubSection->RawDataSize &&
	    SubSection->SubSectionSize >= (LARGE_PAGE_SIZE - PAGE_SIZE)) {
	    Flags |= MEM_RESERVE_LARGE_PAGES;
	}
	IF_ERR_GOTO(err, Status,
		    MmReserveVirtualMemoryEx(VSpace, BaseAddress + SubSection->SubSectionBase,
					     0, SubSection->SubSectionSize, 0, 0, Flags, &Vad));
	assert(Vad != NULL);
	Vad->ImageSectionView.SubSection = SubSection;

	Status = MiCommitImageVad(Vad);
	if (!NT_SUCCESS(Status)) {
	    MmDeleteVad(Vad);
	    goto err;
	}
	InsertTailList(&VadList, &Vad->SectionLink);
    }

    /* All subsections mapped successfully. Add the VADs to the vad list of the section */
    AppendTailListHead(SectionVadList, &VadList);

    if (pBaseAddress != NULL) {
	if (*pBaseAddress != 0) {
	    BaseAddress = *pBaseAddress;
	} else {
	    *pBaseAddress = BaseAddress;
	}
    }
    if (pImageVirtualSize != NULL) {
	*pImageVirtualSize = ImageVirtualSize;
    }
    return STATUS_SUCCESS;

err:
    LoopOverList(Vad, &VadList, MMVAD, SectionLink) {
	MmDeleteVad(Vad);
    }
    return Status;
}

static NTSTATUS MiMapViewOfPhysicalSection(IN PVIRT_ADDR_SPACE VSpace,
					   IN MWORD PhysicalBase,
					   IN MWORD VirtualBase,
					   IN MWORD WindowSize)
{
    assert(VSpace != NULL);
    PMMVAD Vad = NULL;
    RET_ERR(MmReserveVirtualMemoryEx(VSpace, VirtualBase, 0, WindowSize, 0,
				     0, MEM_RESERVE_PHYSICAL_MAPPING, &Vad));
    assert(Vad != NULL);
    Vad->PhysicalSectionView.PhysicalBase = PhysicalBase;
    if (Vad->PhysicalSectionView.RootUntyped) {
	assert(!Vad->PhysicalSectionView.RootUntyped->IsDevice);
    }
    BOOLEAN UseLargePage = IS_LARGE_PAGE_ALIGNED(PhysicalBase) &&
	IS_LARGE_PAGE_ALIGNED(VirtualBase) && IS_LARGE_PAGE_ALIGNED(WindowSize);
    RET_ERR_EX(MiMapIoMemory(Vad->VSpace, PhysicalBase, VirtualBase, WindowSize,
			     MM_RIGHTS_RW, UseLargePage),
	       MmDeleteVad(Vad));
    return STATUS_SUCCESS;
}

NTSTATUS MmMapPhysicalMemory(IN ULONG64 PhysicalBase,
			     IN MWORD VirtualBase,
			     IN MWORD WindowSize)
{
    return MmMapViewOfSection(&MiNtosVaddrSpace, MiPhysicalSection, &VirtualBase,
			      &PhysicalBase, &WindowSize, 0, ViewUnmap, 0, TRUE);
}

/*
 * Map a view of the given section onto the given virtual address space.
 *
 * For now we commit the full view (CommitSize == ViewSize).
 */
NTSTATUS MmMapViewOfSection(IN PVIRT_ADDR_SPACE VSpace,
			    IN PSECTION Section,
			    IN OUT OPTIONAL MWORD *BaseAddress,
			    IN OUT OPTIONAL ULONG64 *SectionOffset,
			    IN OUT OPTIONAL MWORD *ViewSize,
			    IN ULONG HighZeroBits,
			    IN SECTION_INHERIT InheritDisposition,
			    IN ULONG ReserveFlags,
			    IN BOOLEAN AlwaysWritable)
{
    assert(VSpace != NULL);
    assert(Section != NULL);
    if (Section->Flags.Image) {
	if (SectionOffset != NULL) {
	    return STATUS_INVALID_PARAMETER;
	}
	MWORD ImageVirtualSize;
	RET_ERR(MiMapViewOfImageSection(VSpace, &Section->VadList,
					Section->ImageSectionObject,
					BaseAddress, &ImageVirtualSize,	HighZeroBits,
					ReserveFlags, AlwaysWritable));
	if (ViewSize != NULL) {
	    *ViewSize = ImageVirtualSize;
	}
	return STATUS_SUCCESS;
    } else if (Section->Flags.PhysicalMemory) {
	if (!BaseAddress || !*BaseAddress || !SectionOffset || !*SectionOffset
	    || !ViewSize || !*ViewSize) {
	    return STATUS_INVALID_PARAMETER;
	}
	return MiMapViewOfPhysicalSection(VSpace, *SectionOffset, *BaseAddress, *ViewSize);
    }
    UNIMPLEMENTED;
}

NTSTATUS NtCreateSection(IN ASYNC_STATE State,
			 IN PTHREAD Thread,
                         OUT HANDLE *SectionHandle,
                         IN ACCESS_MASK DesiredAccess,
                         IN OPTIONAL OB_OBJECT_ATTRIBUTES ObjectAttributes,
                         IN OPTIONAL PLARGE_INTEGER MaximumSize,
                         IN ULONG SectionPageProtection,
                         IN ULONG SectionAttributes,
                         IN HANDLE FileHandle)
{
    NTSTATUS Status;
    PSECTION Section;

    ASYNC_BEGIN(State, Locals, {
	    PIO_FILE_OBJECT FileObject;
	});

    Locals.FileObject = NULL;

    if (FileHandle) {
	ASYNC_RET_ERR(State, ObReferenceObjectByHandle(Thread, FileHandle,
						       OBJECT_TYPE_FILE,
						       (POBJECT *)&Locals.FileObject));
	assert(Locals.FileObject);
    }

    AWAIT_EX(Status, MmCreateSectionEx, State, Locals, Thread, Locals.FileObject,
	     SectionPageProtection, SectionAttributes, &Section);
    if (!NT_SUCCESS(Status)) {
	goto out;
    }
    assert(Section);
    assert(SectionHandle);
    Status = ObCreateHandle(Thread->Process, Section, FALSE, SectionHandle);
    /* Note here regardless of the return value we want to dereference the
     * section object, because in a successful creation, the returned section
     * object has refcount of one (instead of two, one from ObCreateObject,
     * one from ObCreateHandle). A subsequent NtClose will delete the section. */
    ObDereferenceObject(Section);

out:
    if (Locals.FileObject) {
	ObDereferenceObject(Locals.FileObject);
    }
    ASYNC_END(State, Status);
}

NTSTATUS NtMapViewOfSection(IN ASYNC_STATE AsyncState,
                            IN PTHREAD Thread,
                            IN HANDLE SectionHandle,
                            IN HANDLE ProcessHandle,
                            IN OUT OPTIONAL PPVOID BaseAddress,
                            IN ULONG_PTR HighZeroBits,
                            IN SIZE_T CommitSize,
                            IN OUT OPTIONAL PLARGE_INTEGER SectionOffset,
                            IN OUT PSIZE_T ViewSize,
                            IN SECTION_INHERIT InheritDisposition,
                            IN ULONG AllocationType,
                            IN ULONG AccessProtection)
{
    /* On 64-bit systems the HighZeroBits parameter is interpreted as a bit mask if
     * it is greater than or equal to 32. Convert the bit mask to the number of bits
     * in this case. */
#ifdef _WIN64
    if (HighZeroBits >= 32) {
        HighZeroBits = 64 - RtlFindMostSignificantBit(HighZeroBits) - 1;
    } else if (HighZeroBits) {
	/* The high 32-bits of the allocated address are also required to be zero,
	 * in order to retain compatibility with 32-bit systems. Therefore we need
	 * to increase HighZeroBits by 32. */
	HighZeroBits += 32;
    }
#endif

    if (HighZeroBits > MM_MAXIMUM_ZERO_HIGH_BITS) {
        return STATUS_INVALID_PARAMETER_4;
    }

    if (AllocationType & !(MEM_LARGE_PAGES | MEM_TOP_DOWN | MEM_RESERVE)) {
	return STATUS_INVALID_PARAMETER_9;
    }
    ULONG ReserveFlags = 0;
    if (AllocationType & MEM_LARGE_PAGES) {
	ReserveFlags |= MEM_RESERVE_LARGE_PAGES;
    }
    if (AllocationType & MEM_TOP_DOWN) {
	ReserveFlags |= MEM_RESERVE_TOP_DOWN;
    }

    PSECTION Section = NULL;
    PPROCESS Process = NULL;
    NTSTATUS Status;

    IF_ERR_GOTO(out, Status, ObReferenceObjectByHandle(Thread, SectionHandle,
						       OBJECT_TYPE_SECTION,
						       (POBJECT *)&Section));
    IF_ERR_GOTO(out, Status, ObReferenceObjectByHandle(Thread, ProcessHandle,
						       OBJECT_TYPE_PROCESS,
						       (POBJECT *)&Process));
    Status = MmMapViewOfSection(&Process->VSpace, Section, (MWORD *)BaseAddress,
				(ULONG64 *)SectionOffset, (MWORD *)ViewSize,
				HighZeroBits, InheritDisposition, ReserveFlags,
				AccessProtection & PAGE_READWRITE);

out:
    if (Section) {
	ObDereferenceObject(Section);
    }
    if (Process) {
	ObDereferenceObject(Process);
    }
    return Status;
}

NTSTATUS NtUnmapViewOfSection(IN ASYNC_STATE AsyncState,
                              IN PTHREAD Thread,
                              IN HANDLE ProcessHandle,
                              IN PVOID BaseAddress)
{
    UNIMPLEMENTED;
}

NTSTATUS NtQuerySection(IN ASYNC_STATE State,
			IN PTHREAD Thread,
                        IN HANDLE SectionHandle,
                        IN SECTION_INFORMATION_CLASS SectionInformationClass,
                        IN PVOID SectionInformationBuffer,
                        IN ULONG SectionInformationLength,
                        OUT ULONG *ReturnLength)
{
    assert(ReturnLength);
    if (SectionHandle == NULL) {
	return STATUS_INVALID_HANDLE;
    }
    switch (SectionInformationClass) {
    case SectionBasicInformation:
	if (SectionInformationLength < sizeof(SECTION_BASIC_INFORMATION)) {
	    return STATUS_INFO_LENGTH_MISMATCH;
	}
	break;
    case SectionImageInformation:
	if (SectionInformationLength < sizeof(SECTION_IMAGE_INFORMATION)) {
	    return STATUS_INFO_LENGTH_MISMATCH;
	}
	break;
    default:
	return STATUS_INVALID_INFO_CLASS;
    }

    PSECTION Section = NULL;
    RET_ERR(ObReferenceObjectByHandle(Thread, SectionHandle,
				      OBJECT_TYPE_SECTION, (POBJECT *)&Section));

    if (SectionInformationClass == SectionBasicInformation) {
	PSECTION_BASIC_INFORMATION Info = (PSECTION_BASIC_INFORMATION)SectionInformationBuffer;
	if (Section->Flags.Based) {
	    Info->BaseAddress = (PVOID) Section->BasedSectionNode.Key;
	} else {
	    Info->BaseAddress = 0;
	}
	Info->Attributes = Section->Attributes;
	Info->Size.QuadPart = Section->Size;
	*ReturnLength = sizeof(SECTION_BASIC_INFORMATION);
    } else {
	assert(SectionInformationClass == SectionImageInformation);
	*((PSECTION_IMAGE_INFORMATION)SectionInformationBuffer) = Section->ImageSectionObject->ImageInformation;
	*ReturnLength = sizeof(SECTION_IMAGE_INFORMATION);
    }
    ObDereferenceObject(Section);
    return STATUS_SUCCESS;
}

#ifdef MMDBG
static VOID MiDbgDumpSubSection(IN PSUBSECTION SubSection)
{
    MmDbgPrint("Dumping sub-section %p\n", SubSection);
    if (SubSection == NULL) {
	MmDbgPrint("    (nil)\n");
	return;
    }
    MmDbgPrint("    parent image section object = %p\n", SubSection->ImageSection);
    MmDbgPrint("    sub-section name = %s\n", SubSection->Name);
    MmDbgPrint("    sub-section size = 0x%x\n", SubSection->SubSectionSize);
    MmDbgPrint("    starting file offset = 0x%x\n", SubSection->FileOffset);
    MmDbgPrint("    raw data size = 0x%x\n", SubSection->RawDataSize);
    MmDbgPrint("    sub-section base = 0x%x\n", SubSection->SubSectionBase);
    MmDbgPrint("    image cache file offset = 0x%x\n", SubSection->ImageCacheFileOffset);
    MmDbgPrint("    characteristics = 0x%x\n", SubSection->Characteristics);
}

static VOID MiDbgDumpImageSectionObject(IN PIMAGE_SECTION_OBJECT ImageSection)
{
    MmDbgPrint("Dumping image section object %p\n", ImageSection);
    if (ImageSection == NULL) {
	MmDbgPrint("    (nil)\n");
	return;
    }
    MmDbgPrint("    Number of subsections = %d\n", ImageSection->NumSubSections);
    MmDbgPrint("    Image base = %p\n", (PVOID) ImageSection->ImageBase);
    MmDbgPrint("    TransferAddress = %p\n",
	       (PVOID)ImageSection->ImageInformation.TransferAddress);
    MmDbgPrint("    ZeroBits = 0x%x\n",
	       ImageSection->ImageInformation.ZeroBits);
    MmDbgPrint("    MaximumStackSize = 0x%zx\n",
	       (MWORD)ImageSection->ImageInformation.MaximumStackSize);
    MmDbgPrint("    CommittedStackSize = 0x%zx\n",
	       (MWORD)ImageSection->ImageInformation.CommittedStackSize);
    MmDbgPrint("    SubSystemType = 0x%x\n",
	       ImageSection->ImageInformation.SubSystemType);
    MmDbgPrint("    SubSystemMinorVersion = 0x%x\n",
	       ImageSection->ImageInformation.SubSystemMinorVersion);
    MmDbgPrint("    SubSystemMajorVersion = 0x%x\n",
	       ImageSection->ImageInformation.SubSystemMajorVersion);
    MmDbgPrint("    GpValue = 0x%x\n",
	       ImageSection->ImageInformation.GpValue);
    MmDbgPrint("    ImageCharacteristics = 0x%x\n",
	       ImageSection->ImageInformation.ImageCharacteristics);
    MmDbgPrint("    DllCharacteristics = 0x%x\n",
	       ImageSection->ImageInformation.DllCharacteristics);
    MmDbgPrint("    Machine = 0x%x\n",
	       ImageSection->ImageInformation.Machine);
    if (ImageSection->ImageInformation.ImageContainsCode) {
	MmDbgPrint("    Image contains code\n");
    } else {
	MmDbgPrint("    Image does not contain code\n");
    }
    MmDbgPrint("    ImageFlags = 0x%x\n",
	       ImageSection->ImageInformation.ImageFlags);
    MmDbgPrint("    LoaderFlags = 0x%x\n",
	       ImageSection->ImageInformation.LoaderFlags);
    MmDbgPrint("    ImageFileSize = 0x%x\n",
	       ImageSection->ImageInformation.ImageFileSize);
    MmDbgPrint("    CheckSum = 0x%x\n",
	       ImageSection->ImageInformation.CheckSum);
    MmDbgPrint("    Fcb = %p\n", ImageSection->Fcb);
    MmDbgPrint("    ImageCacheFileSize = 0x%x\n", ImageSection->ImageCacheFileSize);
    MmDbgPrint("    ImageCacheFile = %p\n", ImageSection->ImageCacheFile);
    IoDbgDumpFileObject(ImageSection->ImageCacheFile, 4);
    LoopOverList(SubSection, &ImageSection->SubSectionList, SUBSECTION, Link) {
	MiDbgDumpSubSection(SubSection);
    }
}

static VOID MiDbgDumpDataSectionObject(IN PDATA_SECTION_OBJECT DataSection)
{
    MmDbgPrint("Dumping data section object %p\n", DataSection);
    if (DataSection == NULL) {
	MmDbgPrint("    (nil)\n");
	return;
    }
    MmDbgPrint("    UNIMPLEMENTED\n");
}
#endif

VOID MmDbgDumpSection(PSECTION Section)
{
#ifdef MMDBG
    MmDbgPrint("Dumping section %p (refcount %lld)\n", Section,
	       OBJECT_TO_OBJECT_HEADER(Section)->RefCount);
    if (Section == NULL) {
	MmDbgPrint("    (nil)\n");
    }
    MmDbgPrint("    Flags: %s%s%s%s%s%s\n",
	     Section->Flags.Image ? " image" : "",
	     Section->Flags.Based ? " based" : "",
	     Section->Flags.File ? " file" : "",
	     Section->Flags.PhysicalMemory ? " physical-memory" : "",
	     Section->Flags.Reserve ? " reserve" : "",
	     Section->Flags.Commit ? " commit" : "");
    ObDbgDumpObjectHandles(Section, 4);
    if (Section->Flags.Image) {
	MiDbgDumpImageSectionObject(Section->ImageSectionObject);
    } else {
	MiDbgDumpDataSectionObject(Section->DataSectionObject);
    }
#endif
}
