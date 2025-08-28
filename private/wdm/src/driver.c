#include <wdmp.h>

#define SERVICE_KEY_NAME	(CONTROL_KEY_NAME L"Services\\")

static LIST_ENTRY IopDriverList;

static NTSTATUS IopCallDriverEntry(IN PDRIVER_OBJECT DriverObject)
{
    assert(DriverObject);
    PLDR_DATA_TABLE_ENTRY DriverImage = NULL;
    NTSTATUS Status = LdrFindEntryForAddress(DriverObject->DriverStart,
					     &DriverImage);
    if (!NT_SUCCESS(Status)) {
	return STATUS_DRIVER_ENTRYPOINT_NOT_FOUND;
    }
    assert(DriverImage);
    PDRIVER_INITIALIZE DriverEntry = DriverImage->EntryPoint;
    DbgTrace("Driver entry %p. Registry path %wZ\n",
	     DriverEntry, &DriverObject->RegistryPath);
    Status = DriverEntry(DriverObject, &DriverObject->RegistryPath);
    if (!NT_SUCCESS(Status)) {
	return STATUS_FAILED_DRIVER_ENTRY;
    }
    return STATUS_SUCCESS;
}

static VOID IopCallReinitRoutine(IN PDRIVER_OBJECT DriverObject)
{
    DriverObject->Flags &= ~DRVO_REINIT_REGISTERED;
    LoopOverList(Entry, &DriverObject->ReinitListHead, DRIVER_REINIT_ITEM, ItemEntry) {
	Entry->Count++;
	Entry->ReinitRoutine(Entry->DriverObject, Entry->Context, Entry->Count);
    }
}

static NTSTATUS IopCreateDriverObject(IN PUNICODE_STRING RegistryPath,
				      IN PVOID BaseAddress,
				      OUT PDRIVER_OBJECT *pDriverObject)
{
    /* Get the base name of the driver service from the registry path */
    const UNICODE_STRING PathDividers = RTL_CONSTANT_STRING(L"\\/");
    USHORT Position;
    if (!NT_SUCCESS(RtlFindCharInUnicodeString(RTL_FIND_CHAR_IN_UNICODE_STRING_START_AT_END,
					       RegistryPath, &PathDividers, &Position))) {
	assert(FALSE);
	return STATUS_INTERNAL_ERROR;
    }
    Position += sizeof(WCHAR);
    if (Position >= RegistryPath->Length) {
	assert(FALSE);
	return STATUS_INTERNAL_ERROR;
    }
    IopAllocateObject(DriverObject, DRIVER_OBJECT);
    DriverObject->DriverStart = BaseAddress;
    DriverObject->RegistryPath = *RegistryPath;
    DriverObject->DriverName.Buffer = RegistryPath->Buffer + Position / sizeof(WCHAR);
    DriverObject->DriverName.MaximumLength = DriverObject->DriverName.Length =
	RegistryPath->Length - Position;
    InsertHeadList(&IopDriverList, &DriverObject->ListEntry);
    InitializeListHead(&DriverObject->ReinitListHead);
    *pDriverObject = DriverObject;
    return STATUS_SUCCESS;
}

NTSTATUS IopInitDriverObject(IN PUNICODE_STRING RegistryPath)
{
    InitializeListHead(&IopDriverList);

    PDRIVER_OBJECT DriverObject = NULL;
    NTSTATUS Status = IopCreateDriverObject(RegistryPath,
					    NtCurrentPeb()->ImageBaseAddress,
					    &DriverObject);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    Status = IopCallDriverEntry(DriverObject);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    IopCallReinitRoutine(DriverObject);

    return Status;
}

PDRIVER_OBJECT IopLocateDriverObject(IN PCSTR BaseName)
{
    ULONG BaseNameLength = strlen(BaseName);
    WCHAR BaseNameBuffer[BaseNameLength];
    ULONG UnicodeLength = 0;
    RtlUTF8ToUnicodeN(BaseNameBuffer, BaseNameLength * sizeof(WCHAR),
		      &UnicodeLength, BaseName, BaseNameLength);
    UNICODE_STRING BaseNameU = {
	.Buffer = BaseNameBuffer,
	.Length = UnicodeLength,
	.MaximumLength = sizeof(BaseNameBuffer)
    };
    LoopOverList(DriverObject, &IopDriverList, DRIVER_OBJECT, ListEntry) {
	if (BaseNameLength) {
	    if (!RtlCompareUnicodeString(&BaseNameU, &DriverObject->DriverName, TRUE)) {
		return DriverObject;
	    }
	} else {
	    if (IoIsSingletonMode(DriverObject)) {
		return DriverObject;
	    }
	}
    }
    return NULL;
}

NTSTATUS IopLoadDriver(IN PCSTR BaseName)
{
    if (IopLocateDriverObject(BaseName)) {
	return STATUS_SUCCESS;
    }

    ULONG ServiceBufSize = sizeof(SERVICE_KEY_NAME) + strlen(BaseName) * sizeof(WCHAR) - sizeof(WCHAR);
    IopAllocatePool(DriverService, WCHAR, ServiceBufSize);
    memcpy(DriverService, SERVICE_KEY_NAME, sizeof(SERVICE_KEY_NAME));
    PWCHAR BaseNameU = &DriverService[sizeof(SERVICE_KEY_NAME) / sizeof(WCHAR) - 1];
    ULONG BaseNameLength = 0;
    RET_ERR_EX(RtlUTF8ToUnicodeN(BaseNameU, strlen(BaseName) * sizeof(WCHAR),
				 &BaseNameLength, BaseName, strlen(BaseName)),
	       IopFreePool(DriverService));
    UNICODE_STRING DriverServiceKey = {
	.Buffer = DriverService,
	.Length = sizeof(SERVICE_KEY_NAME) - sizeof(WCHAR) + BaseNameLength,
	.MaximumLength = ServiceBufSize
    };
    PDRIVER_OBJECT DriverObject = NULL;
    HANDLE KeyHandle = NULL;
    PKEY_VALUE_PARTIAL_INFORMATION PartialInfo = NULL;
    NTSTATUS Status;
    IF_ERR_GOTO(out, Status, IopOpenKey(DriverServiceKey, &KeyHandle));
    assert(KeyHandle != NULL);
    IF_ERR_GOTO(out, Status, IopQueryValueKey(KeyHandle, L"ImagePath", &PartialInfo));
    if (!(PartialInfo->Type == REG_SZ || PartialInfo->Type == REG_EXPAND_SZ)) {
	assert(FALSE);
	Status = STATUS_OBJECT_TYPE_MISMATCH;
	goto out;
    }
    PVOID BaseAddress = NULL;
    UNICODE_STRING ImagePath = {
	.Buffer = (PWSTR)PartialInfo->Data,
	.Length = PartialInfo->DataLength,
	.MaximumLength = PartialInfo->DataLength
    };
    IF_ERR_GOTO(out, Status, LdrLoadDll(NULL, NULL, &ImagePath, &BaseAddress));
    Status = IopCreateDriverObject(&DriverServiceKey, BaseAddress, &DriverObject);
    if (!NT_SUCCESS(Status)) {
	LdrUnloadDll(BaseAddress);
	goto out;
    }
    Status = IopCallDriverEntry(DriverObject);
    if (NT_SUCCESS(Status)) {
	IopCallReinitRoutine(DriverObject);
	Status = STATUS_SUCCESS;
    }

out:
    if (!NT_SUCCESS(Status) && !DriverObject) {
	IopFreePool(DriverService);
    }
    if (KeyHandle) {
	NtClose(KeyHandle);
    }
    if (PartialInfo) {
	ExFreePool(PartialInfo);
    }
    return Status;
}

/*
 * @implemented
 *
 * Allocates a per-driver context area and assigns a unique identifier to it.
 * The per-driver context area follows the header IO_CLIENT_EXTENSION which
 * records the identifier and chains all extensions of one driver. The pointer
 * to the beginning of the per-driver context area (ie. the memory immediately
 * after the header) is returned via pDriverExtension.
 *
 * @remarks This routine must be called at PASSIVE_LEVEL.
 */
NTAPI NTSTATUS IoAllocateDriverObjectExtension(IN PDRIVER_OBJECT DriverObject,
					       IN PVOID ClientIdentAddr,
					       IN ULONG DriverExtensionSize,
					       OUT PVOID *pDriverExtension)
{
    PAGED_CODE();

    /* Assume failure */
    *pDriverExtension = NULL;

    /* Make sure client indentification address is not already used */
    for (PIO_CLIENT_EXTENSION DrvExt = DriverObject->ClientDriverExtension;
	 DrvExt != NULL; DrvExt = DrvExt->NextExtension) {
        /* Check if the identifier matches */
        if (DrvExt->ClientIdentificationAddress == ClientIdentAddr) {
            /* We have a collision, return error */
            return STATUS_OBJECT_NAME_COLLISION;
        }
    }

    /* Allocate the driver extension */
    PIO_CLIENT_EXTENSION DrvExt = ExAllocatePoolWithTag(sizeof(IO_CLIENT_EXTENSION)
							+ DriverExtensionSize,
							TAG_DRIVER_EXTENSION);
    if (!DrvExt) {
	return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* Fill out the extension and add it to the driver's client extension list */
    DrvExt->ClientIdentificationAddress = ClientIdentAddr;
    DrvExt->NextExtension =DriverObject->ClientDriverExtension;
    DriverObject->ClientDriverExtension = DrvExt;

    /* Return the pointer to the memory immediately after the header */
    *pDriverExtension = DrvExt + 1;
    return STATUS_SUCCESS;
}

/*
 * @implemented
 *
 * Returns the pointer to the beginning of the per-driver context area
 * (ie. the memory immediately after the header) matching the given identifer.
 *
 * @remarks This routine must be called at PASSIVE_LEVEL.
 */
NTAPI PVOID IoGetDriverObjectExtension(IN PDRIVER_OBJECT DriverObject,
				       IN PVOID ClientIdentAddr)
{
    PAGED_CODE();
    /* Loop the list until we find the right one */
    for (PIO_CLIENT_EXTENSION DrvExt = DriverObject->ClientDriverExtension;
	 DrvExt != NULL; DrvExt = DrvExt->NextExtension) {
        /* Check if the identifier matches */
        if (DrvExt->ClientIdentificationAddress == ClientIdentAddr) {
	    /* Return the pointer to the memory immediately after the header */
	    return DrvExt + 1;
        }
    }
    return NULL;
}

/*
 * @implemented
 *
 * @remarks This routine must be called at PASSIVE_LEVEL.
 */
NTAPI VOID IoRegisterDriverReinitialization(IN PDRIVER_OBJECT DriverObject,
					    IN PDRIVER_REINITIALIZE ReinitRoutine,
					    IN PVOID Context)
{
    PAGED_CODE();
    /* Allocate the entry */
    PDRIVER_REINIT_ITEM ReinitItem = ExAllocatePoolWithTag(sizeof(DRIVER_REINIT_ITEM),
							   TAG_REINIT);
    if (!ReinitItem) {
	return;
    }

    /* Fill it out */
    ReinitItem->DriverObject = DriverObject;
    ReinitItem->ReinitRoutine = ReinitRoutine;
    ReinitItem->Context = Context;
    ReinitItem->Count = 0;

    /* Set the Driver Object flag and insert the entry into the list */
    DriverObject->Flags |= DRVO_REINIT_REGISTERED;
    InsertTailList(&DriverObject->ReinitListHead, &ReinitItem->ItemEntry);
}

NTAPI NTSTATUS
IoRegisterPlugPlayNotification(IN IO_NOTIFICATION_EVENT_CATEGORY EventCategory,
			       IN ULONG EventCategoryFlags,
			       IN OPTIONAL PVOID EventCategoryData,
			       IN PDRIVER_OBJECT DriverObject,
			       IN PDRIVER_NOTIFICATION_CALLBACK_ROUTINE CallbackRoutine,
			       IN OUT OPTIONAL PVOID Context,
			       OUT PVOID *NotificationEntry)
{
    PAGED_CODE();
    UNIMPLEMENTED;
    return STATUS_NOT_IMPLEMENTED;
}

struct _IO_MAPPING_TABLE;

/*
 * This structure represents a virtual memory regions reserved for physical
 * memory mapping in the driver address space for the purpose of memory mapped
 * IO. These memory regions are derived from what seL4 refers to as "device
 * untyped memory". Note that ordinary "non-device" memories are never recorded
 * here. One IO_MEMORY_WINDOW maps a 256MB-aligned physical memory block (on i386)
 * into a 256-MB-aligned virtual address space in the driver address space.
 * Mapping status (ie. whether a page is mapped or not) is managed via multi-level
 * tables similar to page tables. On i386 we use a two-level scheme where each
 * level has 8 bits (so the total window size is 2^(8+8+12) = 256MB). On amd64
 * we use four levels, so each window spans 2^(8*4+12) = 16TB.
 */
typedef struct _IO_MEMORY_WINDOW {
    ULONG64 PhysicalBase;
    PVOID VirtualBase;
    struct _IO_MAPPING_TABLE *Table;
    struct _IO_MEMORY_WINDOW *Next;
    MEMORY_CACHING_TYPE CacheType;
} IO_MEMORY_WINDOW, *PIO_MEMORY_WINDOW;

#define IO_MAPPING_TABLE_BITS	8
#define IO_MAPPING_TABLE_SIZE	(1 << IO_MAPPING_TABLE_BITS)
#define IO_MAPPING_TABLE_LEVELS	(sizeof(PVOID) / 2)
#define IO_MEMORY_WINDOW_BITS					\
    (PAGE_LOG2SIZE + IO_MAPPING_TABLE_BITS * IO_MAPPING_TABLE_LEVELS)
#define IO_MEMORY_WINDOW_SIZE	(1ULL << IO_MEMORY_WINDOW_BITS)
#define IO_WINDOW_ALIGN(x)	ALIGN_DOWN_64(x, IO_MEMORY_WINDOW_SIZE)
#define IO_WINDOW_ALIGNED(x)	((ULONG64)(x) == IO_WINDOW_ALIGN(x))

/*
 * Represents one level of physical memory mapping status. Note here PVOID is
 * a pointer to the next lower level IO_MAPPING_TABLE unless we are the lowest
 * level of mapping status table, in which case PVOID is a pointer to an
 * RTL_BITMAP object.
 */
typedef struct _IO_MAPPING_TABLE {
    PVOID Entries[IO_MAPPING_TABLE_SIZE];
} IO_MAPPING_TABLE, *PIO_MAPPING_TABLE;

static PIO_MEMORY_WINDOW IopIoMemoryWindow;

static PIO_MEMORY_WINDOW MiGetIoMemoryWindow(IN ULONG64 PhysicalAddress,
					     IN MEMORY_CACHING_TYPE CacheType)
{
    ULONG64 PhysicalBase = IO_WINDOW_ALIGN(PhysicalAddress);
    for (PIO_MEMORY_WINDOW Ptr = IopIoMemoryWindow; Ptr; Ptr = Ptr->Next) {
	if (PhysicalBase == Ptr->PhysicalBase && CacheType == Ptr->CacheType) {
	    return Ptr;
	}
    }
    PIO_MEMORY_WINDOW Ptr = ExAllocatePool(sizeof(IO_MEMORY_WINDOW));
    if (!Ptr) {
	return NULL;
    }
    Ptr->PhysicalBase = PhysicalBase;
    NTSTATUS Status = WdmReserveIoMemoryWindow(PhysicalBase, IO_MEMORY_WINDOW_BITS,
					       CacheType, &Ptr->VirtualBase);
    if (!NT_SUCCESS(Status)) {
	ExFreePool(Ptr);
	return NULL;
    }
    assert(Ptr->VirtualBase);
    Ptr->CacheType = CacheType;
    Ptr->Next = IopIoMemoryWindow;
    IopIoMemoryWindow = Ptr;
    return Ptr;
}

FORCEINLINE ULONG MiGetIoMappingTableIndex(IN ULONG64 Offset,
					   IN ULONG Level)
{
    return (Offset >> (PAGE_LOG2SIZE + IO_MAPPING_TABLE_BITS * Level)) &
	(IO_MAPPING_TABLE_SIZE - 1);
}

#define ALLOCATE_TABLE_OR_RETURN(Tbl, Ptr)			\
    Tbl = Ptr;							\
    if (!(Tbl) && Allocate) {					\
	Ptr = Tbl = ExAllocatePool(sizeof(IO_MAPPING_TABLE));	\
    }								\
    if (!(Tbl)) {						\
	return NULL;						\
    }

static PRTL_BITMAP MiGetIoMappingStatus(IN PIO_MEMORY_WINDOW Window,
					IN ULONG64 Offset,
					IN BOOLEAN Allocate)
{
    ULONG Index = MiGetIoMappingTableIndex(Offset, 1);
    PIO_MAPPING_TABLE Table;
    /* For i386 we have two levels of mapping status table, so simply
     * return the pointer to the RTL_BITMAP indexed by the offset bits
     * that correspond to the top-level table. */
    ALLOCATE_TABLE_OR_RETURN(Table, Window->Table);
    if (IO_MAPPING_TABLE_LEVELS == 4) {
	/* For amd64 we have four levels of mapping status table, so
	 * perform two more indexings into the multi-level table. */
	ULONG Index1 = MiGetIoMappingTableIndex(Offset, 2);
	ULONG Index2 = MiGetIoMappingTableIndex(Offset, 3);
	assert(Window->Table);
	assert(Table == Window->Table);
	PIO_MAPPING_TABLE Table1;
	ALLOCATE_TABLE_OR_RETURN(Table1, Table->Entries[Index2]);
	ALLOCATE_TABLE_OR_RETURN(Table, Table1->Entries[Index1]);
    }
    PRTL_BITMAP Bitmap = Table->Entries[Index];
    if (!Bitmap && Allocate) {
	Bitmap = ExAllocatePool(sizeof(RTL_BITMAP));
	if (!Bitmap) {
	    return NULL;
	}
	PULONG BitmapBuffer = ExAllocatePool(IO_MAPPING_TABLE_SIZE / 8);
	if (!BitmapBuffer) {
	    ExFreePool(Bitmap);
	    return NULL;
	}
	RtlInitializeBitMap(Bitmap, BitmapBuffer, IO_MAPPING_TABLE_SIZE);
	Table->Entries[Index] = Bitmap;
    }
    return Bitmap;
}

FORCEINLINE BOOLEAN MiGetSetIoAllocationBitmap(IN PRTL_BITMAP Bitmap,
					       IN OUT ULONG64 *StartAddress,
					       IN ULONG64 EndAddress,
					       IN BOOLEAN Set)
{
    ULONG64 StartPageNum = *StartAddress >> PAGE_LOG2SIZE;
    ULONG64 EndPageNum = EndAddress >> PAGE_LOG2SIZE;
    ULONG NumPages = min(EndPageNum - StartPageNum, IO_MAPPING_TABLE_SIZE);
    ULONG StartBit = StartPageNum & (IO_MAPPING_TABLE_SIZE - 1);
    BOOLEAN Result = FALSE;
    if (Set) {
	RtlSetBits(Bitmap, StartBit, NumPages);
    } else {
	Result = RtlAreBitsSet(Bitmap, StartBit, NumPages);
    }
    ULONG TableWindowSize = 1ULL << (PAGE_LOG2SIZE + IO_MAPPING_TABLE_BITS);
    *StartAddress = ALIGN_DOWN_64(*StartAddress + TableWindowSize, TableWindowSize);
    return Result;
}

/* StartingOffset is the offset within the IO_MEMORY_WINDOW. */
static BOOLEAN MiIsIoWindowMapped(IN PIO_MEMORY_WINDOW Window,
				  IN ULONG64 StartingOffset,
				  IN ULONG64 WindowSize)
{
    assert(Window);
    assert(StartingOffset + WindowSize <= IO_MEMORY_WINDOW_SIZE);
    ULONG64 Offset = StartingOffset;
    while (Offset < StartingOffset + WindowSize) {
	PRTL_BITMAP Bitmap = MiGetIoMappingStatus(Window, Offset, FALSE);
	if (!Bitmap) {
	    return FALSE;
	}
	if (!MiGetSetIoAllocationBitmap(Bitmap, &Offset,
					StartingOffset + WindowSize, FALSE)) {
	    return FALSE;
	}
    }
    return TRUE;
}

/*
 * @remarks This routine must be called at PASSIVE_LEVEL.
 */
NTAPI PVOID MmMapIoSpace(IN PHYSICAL_ADDRESS PhysicalAddress,
			 IN SIZE_T NumberOfBytes,
			 IN MEMORY_CACHING_TYPE CacheType)
{
    PAGED_CODE();
    /* Make sure the address window to be mapped does not span more than one
     * IO memory window. */
    ULONG64 StartAddress = PAGE_ALIGN64(PhysicalAddress.QuadPart);
    ULONG64 EndAddress = PAGE_ALIGN_UP64(PhysicalAddress.QuadPart + NumberOfBytes);
    if ((StartAddress >> IO_MEMORY_WINDOW_BITS) != (EndAddress >> IO_MEMORY_WINDOW_BITS)) {
	/* In this case drivers should map the IO memories in two or more calls to this
	 * routine. We assert so the driver authors can know. */
	assert(FALSE);
	return NULL;
    }
    ULONG64 WindowSize = EndAddress - StartAddress;
    PIO_MEMORY_WINDOW Window = MiGetIoMemoryWindow(StartAddress, CacheType);
    if (!Window) {
	return NULL;
    }
    ULONG64 WindowOffset = PhysicalAddress.QuadPart - Window->PhysicalBase;
    MWORD VirtAddr = WindowOffset + (MWORD)Window->VirtualBase;
    if (MiIsIoWindowMapped(Window, PAGE_ALIGN64(WindowOffset), WindowSize)) {
	return (PVOID)VirtAddr;
    }
    if (!NT_SUCCESS(WdmMapIoMemory(PAGE_ALIGN(VirtAddr), WindowSize))) {
	return NULL;
    }
    for (ULONG64 CurrentAddress = StartAddress; CurrentAddress < EndAddress; ) {
	PRTL_BITMAP Bitmap = MiGetIoMappingStatus(Window,
						  CurrentAddress - Window->PhysicalBase,
						  TRUE);
	if (!Bitmap) {
	    return NULL;
	}
	MiGetSetIoAllocationBitmap(Bitmap, &CurrentAddress, EndAddress, TRUE);
    }
    return (PVOID)VirtAddr;
}

/*
 * @remarks This routine must be called at PASSIVE_LEVEL.
 */
NTAPI VOID MmUnmapIoSpace(IN PVOID BaseAddress,
			  IN SIZE_T NumberOfBytes)
{
    PAGED_CODE();
}

NTAPI NTSTATUS MmAllocateContiguousMemorySpecifyCache(IN SIZE_T NumberOfBytes,
						      IN PHYSICAL_ADDRESS HighestAddr,
						      IN PHYSICAL_ADDRESS Alignment,
						      IN MEMORY_CACHING_TYPE CacheType,
						      OUT PVOID *VirtBase,
						      OUT PHYSICAL_ADDRESS *PhysBase)
{
    ULONG BoundaryAddressBits = RtlFindLeastSignificantBit(Alignment.QuadPart) + 1;
    return WdmHalAllocateDmaBuffer(NumberOfBytes, &HighestAddr,
				   BoundaryAddressBits, CacheType,
				   VirtBase, PhysBase);
}
