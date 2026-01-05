#include "lnxdrvp.h"
#include <hal.h>
#include <pci.h>
#include <stdio.h>
#include <ctype.h>

typedef struct _LNX_DRV_LOADED_MODULE {
    PWSTR ModulePath;
    PVOID ViewBase;
    SIZE_T ViewSize;
    PCSTR Args;
    LIST_ENTRY Link;
} LNX_DRV_LOADED_MODULE, *PLNX_DRV_LOADED_MODULE;

static LNX_DRV_EXPORT_TABLE LnxDrvExportTable;
static LIST_ENTRY LnxDrvPendingIrpList;
static KTIMER LnxDrvGlobalTimer;
static KDPC LnxDrvGlobalTimerDpc;
static KDPC LnxDrvSoftirqDpc;
static IO_WORKITEM LnxDrvIrpCompletionWorkItem;
static SLIST_HEADER LnxDrvCompletionIrpList;
static PCSTR LnxDrvModulesAlias;
static SIZE_T LnxDrvModulesAliasSize;
static PCSTR LnxDrvModulesDep;
static SIZE_T LnxDrvModulesDepSize;
static LIST_ENTRY LnxDrvLoadedModules;
static BOOLEAN LnxDrvDbgPrintOnScreen;

static VOID LnxDbgPrint(IN PCSTR String)
{
#if DBG
    IoDbgPrintMsg(String);
#else
    if (LnxDrvDbgPrintOnScreen) {
	NtDisplayStringA(String);
    }
#endif
}

static NTSTATUS LnxAllocatePhysicalMemory(IN ULONG Order,
					  IN OUT PULONG_PTR Flags,
					  OUT PVOID *VirtAddr,
					  OUT ULONG_PTR *PhyAddr)
{
    MEMORY_CACHING_TYPE CacheType = MmCached;
    PHYSICAL_ADDRESS Res = {};
    NTSTATUS Status = MmAllocateContiguousMemorySpecifyCache(1ULL << (Order + PAGE_SHIFT),
							     Res, Res, CacheType,
							     VirtAddr, &Res);
    if (!NT_SUCCESS(Status)) {
	*VirtAddr = NULL;
	*PhyAddr = 0;
    } else {
	*PhyAddr = Res.QuadPart;
    }
    return Status;
}

static VOID LnxFreePhysicalMemory(IN ULONG Order,
				  IN ULONG_PTR Flags,
				  IN PVOID VirtAddr)
{
    MEMORY_CACHING_TYPE CacheType = MmCached;
    MmFreeContiguousMemorySpecifyCache(VirtAddr, 1ULL << (Order + PAGE_SHIFT), CacheType);
}

static NTSTATUS LnxMapPhysicalMemory(IN PULONG_PTR PfnDb,
				     IN ULONG PfnCount,
				     OUT PVOID *VirtBase)
{
    return MmMapPhysicalMemory(PfnDb, PfnCount, VirtBase);
}

static NTSTATUS LnxReserveVirtualMemory(IN SIZE_T Size,
					IN ULONG_PTR Flags,
					OUT PVOID *VirtAddr)
{
    *VirtAddr = NULL;
    return NtAllocateVirtualMemory(NtCurrentProcess(), VirtAddr, 0, &Size,
				   MEM_RESERVE, PAGE_READWRITE);
}

static NTSTATUS LnxCommitVirtualMemory(IN PVOID VirtAddr,
				       IN SIZE_T Size,
				       IN OPTIONAL SIZE_T PfndbSize,
				       OUT OPTIONAL ULONG_PTR *Pfndb)
{
    if (!VirtAddr) {
	return STATUS_INVALID_PARAMETER;
    }
    return NtAllocateVirtualMemory(NtCurrentProcess(), &VirtAddr, 0, &Size,
				   MEM_COMMIT, PAGE_READWRITE);
}

static VOID LnxFreeVirtualMemory(IN PCVOID Ptr,
				 IN SIZE_T Size,
				 IN BOOLEAN Unreserve)
{
    NtFreeVirtualMemory(NtCurrentProcess(), (PPVOID)&Ptr, &Size,
			Unreserve ? MEM_RELEASE : MEM_DECOMMIT);
}

static PVOID LnxAllocatePool(IN SIZE_T Size)
{
    return ExAllocatePool(NonPagedPool, Size);
}

static VOID LnxFreePool(IN PCVOID Ptr)
{
    ExFreePool(Ptr);
}

static VOID LnxGetSystemRamInfo(OUT ULONG_PTR *TotalRamPages, OUT ULONG_PTR *FreeRamPages)
{
    *TotalRamPages = *FreeRamPages = 0;
    SYSTEM_BASIC_INFORMATION BasicInfo;
    NTSTATUS Status = NtQuerySystemInformation(SystemBasicInformation,
					       &BasicInfo, sizeof(BasicInfo), NULL);
    if (!NT_SUCCESS(Status)) {
	return;
    }
    SYSTEM_PERFORMANCE_INFORMATION PerfInfo;
    Status = NtQuerySystemInformation(SystemPerformanceInformation,
				      &PerfInfo, sizeof(PerfInfo), NULL);
    if (!NT_SUCCESS(Status)) {
	return;
    }
    *TotalRamPages = BasicInfo.NumberOfPhysicalPages;
    *FreeRamPages = PerfInfo.AvailablePages;
}

static PVOID LnxMapIoSpace(IN PLARGE_INTEGER PhysicalAddress,
			   IN PLARGE_INTEGER Length,
			   IN LNXDRV_MEMORY_CACHING_TYPE PageAttribute)
{
    C_ASSERT((ULONG)LnxDrvMemNonCached == (ULONG)MmNonCached);
    C_ASSERT((ULONG)LnxDrvMemCached == (ULONG)MmCached);
    C_ASSERT((ULONG)LnxDrvMemWriteCombined == (ULONG)MmWriteCombined);
    C_ASSERT((ULONG)LnxDrvMemWriteThrough == (ULONG)MmWriteThrough);
    return MmMapIoSpace(*PhysicalAddress, Length->QuadPart, (ULONG)PageAttribute);
}

static VOID LnxUnmapIoSpace(IN PVOID BaseAddress,
			    IN PLARGE_INTEGER Length)
{
    MmUnmapIoSpace(BaseAddress, Length->QuadPart);
}

static VOID LnxInitializeSoftirqDpc(IN PLNX_DPC_CALLBACK Callback,
				    IN PVOID Context)
{
    KeInitializeDpc(&LnxDrvSoftirqDpc, (PVOID)Callback, Context);
}

static VOID LnxQueueSoftirqDpc(IN PVOID Arg1, IN PVOID Arg2)
{
    KeInsertQueueDpc(&LnxDrvSoftirqDpc, Arg1, Arg2);
}

static PVOID LnxAllocateEvent(IN BOOLEAN WaitAll)
{
    PKEVENT Event = ExAllocatePool(NonPagedPool, sizeof(KEVENT));
    if (!Event) {
	return NULL;
    }
    KeInitializeEvent(Event, WaitAll ? NotificationEvent : SynchronizationEvent, FALSE);
    return Event;
}

static VOID LnxFreeEvent(IN PVOID Event)
{
    KeClearEvent(Event);
    ExFreePool(Event);
}

static VOID LnxSetEvent(IN PVOID Event)
{
    KeSetEvent(Event);
}

static VOID LnxClearEvent(IN PVOID Event)
{
    KeClearEvent(Event);
}

static VOID LnxWaitForSingleObject(IN PVOID Event, IN BOOLEAN Alertable)
{
    KeWaitForSingleObject(Event, Executive, KernelMode, Alertable, NULL);
}

static PVOID LnxAllocateWorkItem(IN ULONG ExtensionSize)
{
    PIO_WORKITEM WorkItem = ExAllocatePool(NonPagedPool,
					   sizeof(IO_WORKITEM) + ExtensionSize);
    if (!WorkItem) {
	return NULL;
    }
    IoInitializeWorkItem(NULL, WorkItem);
    return WorkItem;
}

static VOID LnxFreeWorkItem(IN PVOID WorkItem)
{
    ExFreePool(WorkItem);
}

static PVOID LnxGetWorkItemExtension(IN PVOID WorkItem)
{
    return (PIO_WORKITEM)WorkItem + 1;
}

static VOID LnxQueueWorkItem(IN PVOID Handle,
			     IN PLNX_WORKITEM_CALLBACK Callback)
{
    PIO_WORKITEM WorkItem = Handle;
    IoQueueWorkItem(WorkItem, (PVOID)Callback, DelayedWorkQueue, WorkItem + 1);
}

static DEVICE_TYPE LnxDeviceClassToType(IN LNX_DEVICE_TYPE DevType)
{
    switch (DevType) {
    case LnxCharDev:
	return FILE_DEVICE_UNKNOWN;
    case LnxNetDev:
	return FILE_DEVICE_PHYSICAL_NETCARD;
    default:
	return FILE_DEVICE_UNKNOWN;
    }
}

static NTSTATUS LnxConnectInterrupt(OUT PVOID *InterruptObject,
				    IN PLNX_ISR_CALLBACK Callback,
				    IN PVOID Context,
				    IN ULONG Irq)
{
    return IoConnectInterrupt((PVOID)InterruptObject, (PVOID)Callback, Context, Irq,
			      Irq, Irq, Latched, FALSE, ~0UL, TRUE);
}

static VOID LnxDisconnectInterrupt(IN PVOID InterruptObject)
{
    IoDisconnectInterrupt(InterruptObject);
}

static NTSTATUS LnxCreateDevice(OUT PVOID *Handle,
				IN PVOID DriverObject,
				IN ULONG DevExtSize,
				IN PCSTR DevName,
				IN LNX_DEVICE_TYPE DeviceType,
				IN BOOLEAN Exclusive)
{
    *Handle = NULL;
    WCHAR DevNameBuf[256] = {};
    UNICODE_STRING DevNameU = {};
    RtlInitEmptyUnicodeString(&DevNameU, DevNameBuf, sizeof(DevNameBuf));
    ANSI_STRING DevNameA = {};
    RtlInitAnsiString(&DevNameA, DevName);
    RtlAnsiStringToUnicodeString(&DevNameU, &DevNameA, FALSE);

    /* Reject the device name if it contains any of the following characters */
    UNICODE_STRING InvalidChars = RTL_CONSTANT_STRING(L"\\/");
    USHORT Position = USHORT_MAX;
    if (NT_SUCCESS(RtlFindCharInUnicodeString(0, &DevNameU, &InvalidChars, &Position))) {
	return STATUS_OBJECT_NAME_INVALID;
    }

    _snwprintf(DevNameBuf, ARRAYSIZE(DevNameBuf), L"%ws\\%hs",
	       LNXDRV_DEV_OBJ_PATH, DevName);
    RtlInitUnicodeString(&DevNameU, DevNameBuf);

    PDEVICE_OBJECT DeviceObject = NULL;
    NTSTATUS Status = IoCreateDevice(DriverObject, DevExtSize, &DevNameU,
				     LnxDeviceClassToType(DeviceType),
				     FILE_DEVICE_SECURE_OPEN | DO_DIRECT_IO | DO_MAP_IO_BUFFER,
				     Exclusive, &DeviceObject);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }
    *Handle = DeviceObject;
    return STATUS_SUCCESS;
}

static PVOID LnxGetDeviceExtension(IN PVOID Handle)
{
    PDEVICE_OBJECT DevObj = Handle;
    return DevObj->DeviceExtension;
}

static NTSTATUS LnxAttachDevice(IN PVOID SourceDevice,
				IN PVOID TargetDevice,
				OUT PVOID *PreviousTopDevice)
{
    return IoAttachDeviceToDeviceStackSafe(SourceDevice, TargetDevice,
					   (PDEVICE_OBJECT *)PreviousTopDevice);
}

static VOID LnxDeleteDevice(IN PVOID Handle)
{
    IoDeleteDevice(Handle);
}

static NTSTATUS LnxGetDeviceSlotAddress(IN PVOID DeviceObject,
					OUT ULONG *BusNumber,
					OUT ULONG *SlotId)
{
    ULONG Length;
    NTSTATUS Status = IoGetDeviceProperty(DeviceObject,
					  DevicePropertyBusNumber,
					  sizeof(ULONG),
					  BusNumber,
					  &Length);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }
    assert(Length == sizeof(ULONG));
    Status = IoGetDeviceProperty(DeviceObject,
				 DevicePropertyAddress,
				 sizeof(ULONG),
				 SlotId,
				 &Length);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }
    assert(Length == sizeof(ULONG));
    return STATUS_SUCCESS;
}

static NTSTATUS LnxReadPciConfig(IN PVOID Pdo,
				 IN ULONG Offset,
				 OUT PVOID Buffer,
				 IN ULONG Size)
{
    return IoReadPciConfigSpace(Pdo, Buffer, Offset, &Size);
}

static NTSTATUS LnxWritePciConfig(IN PVOID Pdo,
				  IN ULONG Offset,
				  IN PCVOID Buffer,
				  IN ULONG Size)
{
    return IoWritePciConfigSpace(Pdo, Buffer, Offset, &Size);
}

#if defined(__i386__) || defined (__x86_64__)
static UCHAR LnxReadIoPort8(IN USHORT PortNum)
{
    return __inbyte(PortNum);
}

static USHORT LnxReadIoPort16(IN USHORT PortNum)
{
    return __inword(PortNum);
}

static ULONG LnxReadIoPort32(IN USHORT PortNum)
{
    return __indword(PortNum);
}

static VOID LnxWriteIoPort8(IN USHORT PortNum, IN UCHAR Value)
{
    __outbyte(PortNum, Value);
}

static VOID LnxWriteIoPort16(IN USHORT PortNum, IN USHORT Value)
{
    __outword(PortNum, Value);
}

static VOID LnxWriteIoPort32(IN USHORT PortNum, IN ULONG Value)
{
    __outdword(PortNum, Value);
}
#endif

static VOID LnxSetFileExtension(IN PVOID FileObject, IN PVOID FileExtension)
{
    ((PFILE_OBJECT)FileObject)->FsContext2 = FileExtension;
}

static PVOID LnxGetFileExtension(IN PVOID FileObject)
{
    return ((PFILE_OBJECT)FileObject)->FsContext2;
}

static PCSTR LnxGetFileName(IN PVOID FileObjectPtr)
{
    PFILE_OBJECT FileObject = FileObjectPtr;
    UNICODE_STRING PathNameU = FileObject->FileName;
    ULONG Length = 0;
    RtlUnicodeToUTF8N(NULL, ULONG_MAX, &Length, PathNameU.Buffer, PathNameU.Length);
    Length++;
    PCHAR PathName = ExAllocatePool(NonPagedPool, Length);
    if (!PathName) {
	return NULL;
    }
    RtlUnicodeToUTF8N(PathName, Length, &Length, PathNameU.Buffer, PathNameU.Length);
    PathName[Length-1] = '\0';
    return PathName;
}

static ULONG LnxIsFileReadable(IN PVOID FileObject)
{
    return ((PFILE_OBJECT)FileObject)->ReadAccess;
}

static ULONG LnxIsIsFileWritable(IN PVOID FileObject)
{
    return ((PFILE_OBJECT)FileObject)->WriteAccess;
}

static NTSTATUS LnxForwardIrp(IN PVOID DeviceObject,
			      IN PVOID Irp)
{
    BOOLEAN Success = IoForwardIrpSynchronously(DeviceObject, Irp);
    if (!Success) {
	return STATUS_UNSUCCESSFUL;
    }
    return ((PIRP)Irp)->IoStatus.Status;
}

static NTAPI VOID LnxIrpCompletionWorkerRoutine(IN PDEVICE_OBJECT Unused,
						IN PVOID Context)
{
    PSLIST_ENTRY Entry;
    while ((Entry = RtlInterlockedPopEntrySList(&LnxDrvCompletionIrpList))) {
	PIRP Irp = CONTAINING_RECORD(Entry, IRP, Tail.SListEntry);
	IoCompleteRequest(Irp, 0);
    }
}

/* We use Irp::Tail.DriverContext[0] to store whether the IRP is pending (ie.
 * LnxDrvCompleteOrPendIrp has been called for the IRP with a pending state),
 * or whether LnxCompleteIrp has been called for the IRP. This is so that we
 * don't add an already completed IRP (or one already queued for completion)
 * to the pending IRP list. */
#define IRP_PENDING	((PVOID)(ULONG_PTR)1)
#define IRP_COMPLETED	((PVOID)(ULONG_PTR)2)

static VOID LnxCompleteIrp(IN PVOID Ctx,
			   IN NTSTATUS Status,
			   IN ULONG_PTR Information)
{
    assert(Status != STATUS_PENDING);
    PIRP Irp = Ctx;
    PVOID IrpState = InterlockedExchangePointer((PVOID)Irp->Tail.DriverContext, IRP_COMPLETED);
    if (IrpState == IRP_PENDING) {
	RemoveEntryList(&Irp->Tail.ListEntry);
    }
    assert(Irp->Tail.DriverContext[1]);
    if (Irp->Tail.DriverContext[1]) {
	LnxFreeEvent(Irp->Tail.DriverContext[1]);
	Irp->Tail.DriverContext[1] = NULL;
    }
    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = Information;
    if (IoThreadIsAtPassiveLevel()) {
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
    } else if (IrpState != IRP_COMPLETED) {
	RtlInterlockedPushEntrySList(&LnxDrvCompletionIrpList, &Irp->Tail.SListEntry);
	IoQueueWorkItem(&LnxDrvIrpCompletionWorkItem,
			LnxIrpCompletionWorkerRoutine, DelayedWorkQueue, NULL);
    }
}

static PVOID LnxGetIrpDriverContext(IN PVOID Irp)
{
    return ((PIRP)Irp)->Tail.DriverContext[2];
}

static VOID LnxSetIrpDriverContext(IN PVOID Irp, IN PVOID Ctx)
{
    ((PIRP)Irp)->Tail.DriverContext[2] = Ctx;
}

static PVOID LnxIrpGetRequestBuffer(IN PVOID Irp)
{
    return ((PIRP)Irp)->MdlAddress ?
	MmGetSystemAddressForMdlSafe(((PIRP)Irp)->MdlAddress) : ((PIRP)Irp)->UserBuffer;
}

static ULONG LnxIrpGetRequestLength(IN PVOID Irp)
{
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
    assert(Stack->MajorFunction == IRP_MJ_READ || Stack->MajorFunction == IRP_MJ_WRITE);
    return Stack->Parameters.Read.Length;
}

static NTSTATUS LnxRegisterModule(IN PCSTR Name,
				  IN PVOID StartAddr,
				  IN SIZE_T Size)
{
    return LdrRegisterElfModule(StartAddr, NULL, Size, NULL, Name);
}

static NTSTATUS LnxDrvCallAddModule(IN PLNX_DRV_LOADED_MODULE Module,
				    IN PKEVENT Event)
{
    assert(LnxDrvExportTable.AddModule);
    NTSTATUS Status = LnxDrvExportTable.AddModule(Module->ViewBase, Module->ViewSize,
						  Module->Args, Event);
    if (NT_SUCCESS(Status)) {
	NtUnmapViewOfSection(NtCurrentProcess(), Module->ViewBase);
	Module->ViewBase = NULL;
	InsertTailList(&LnxDrvLoadedModules, &Module->Link);
    }
    return Status;
}

static NTAPI VOID LnxAddModuleWorkerRoutine(IN PDEVICE_OBJECT Unused,
					    IN PVOID Context)
{
    PLNX_DRV_LOADED_MODULE Module = Context;
    assert(Module);
    assert(Module->ViewBase);
    assert(Module->ViewSize);
    KEVENT Event;
    KeInitializeEvent(&Event, SynchronizationEvent, FALSE);
    assert(Module->ViewBase);
    assert(Module->ViewSize);
    assert(Module->Args);
    NTSTATUS Status = LnxDrvCallAddModule(Module, &Event);
    if (!NT_SUCCESS(Status)) {
	RtlRaiseStatus(Status);
    }
    KeClearEvent(&Event);
}

static NTSTATUS LnxDrvOpenFile(IN PWSTR FilePath,
			       IN ACCESS_MASK DesiredAccess,
			       OUT HANDLE *FileHandle)
{
    UNICODE_STRING FilePathU;
    RtlInitUnicodeString(&FilePathU, FilePath);

    OBJECT_ATTRIBUTES ObjectAttributes;
    InitializeObjectAttributes(&ObjectAttributes, &FilePathU,
			       OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    IO_STATUS_BLOCK IoStatus;
    return NtCreateFile(FileHandle, DesiredAccess | FILE_READ_DATA | SYNCHRONIZE,
			&ObjectAttributes, &IoStatus, NULL, FILE_ATTRIBUTE_NORMAL,
			FILE_SHARE_READ, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT,
			NULL, 0);
}

static NTSTATUS LnxDrvMapFileSection(IN PWSTR FilePath,
				     OUT PVOID *BaseAddress,
				     OUT SIZE_T *ViewSize,
				     OUT OPTIONAL SIZE_T *FileSize)
{
    HANDLE FileHandle;
    NTSTATUS Status = LnxDrvOpenFile(FilePath, 0, &FileHandle);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    if (FileSize) {
	IO_STATUS_BLOCK IoStatus;
	FILE_STANDARD_INFORMATION FileInfo;
	Status = NtQueryInformationFile(FileHandle, &IoStatus, &FileInfo,
					sizeof(FILE_STANDARD_INFORMATION),
					FileStandardInformation);
	if (!NT_SUCCESS(Status)) {
	    NtClose(FileHandle);
	    return Status;
	}
	*FileSize = FileInfo.EndOfFile.QuadPart;
    }

    HANDLE SectionHandle;
    Status = NtCreateSection(&SectionHandle,
			     SECTION_MAP_READ,
			     NULL,
			     NULL, /* Map full size of file */
			     PAGE_READONLY,
			     SEC_COMMIT,
			     FileHandle);
    NtClose(FileHandle);

    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    Status = NtMapViewOfSection(SectionHandle,
				NtCurrentProcess(),
				BaseAddress,
				0, 0, NULL,
				ViewSize,
				ViewUnmap, 0,
				PAGE_READONLY);
    NtClose(SectionHandle);
    return Status;
}

static NTSTATUS LnxDrvLoadModule(IN PWSTR ModulePath,
				 IN OPTIONAL PKEVENT Event)
{
    /* Check if we already have the module loaded. */
    LoopOverList(Module, &LnxDrvLoadedModules, LNX_DRV_LOADED_MODULE, Link) {
	if (!wcscmp(ModulePath, Module->ModulePath)) {
	    DPRINT("Module %ws already loaded\n", ModulePath);
	    return STATUS_SUCCESS;
	}
    }

    DPRINT("Mapping module %ws\n", ModulePath);
    PVOID BaseAddress = NULL;
    SIZE_T ViewSize = 0;
    NTSTATUS Status = LnxDrvMapFileSection(ModulePath, &BaseAddress, &ViewSize, NULL);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }
    DPRINT("Module file %ws mapped at: %p, size: 0x%zx\n", ModulePath,
	   BaseAddress, ViewSize);

    PLNX_DRV_LOADED_MODULE Module = ExAllocatePool(NonPagedPool,
						   sizeof(LNX_DRV_LOADED_MODULE));
    if (!Module) {
	Status = STATUS_INSUFFICIENT_RESOURCES;
	goto out;
    }
    ULONG PathLength = (wcslen(ModulePath) + 1) * sizeof(WCHAR);
    Module->ModulePath = ExAllocatePool(NonPagedPool, PathLength);
    if (!Module->ModulePath) {
	ExFreePool(Module);
	return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlCopyMemory(Module->ModulePath, ModulePath, PathLength);
    Module->ViewBase = BaseAddress;
    Module->ViewSize = ViewSize;
    Module->Args = "";

    if (Event) {
	KeClearEvent(Event);
	Status = LnxDrvCallAddModule(Module, Event);
    } else {
	PIO_WORKITEM WorkItem = IoAllocateWorkItem(NULL);
	if (!WorkItem) {
	    Status = STATUS_INSUFFICIENT_RESOURCES;
	    goto out;
	}
	IoQueueWorkItem(WorkItem, LnxAddModuleWorkerRoutine, DelayedWorkQueue, Module);
	Status = STATUS_SUCCESS;
    }

out:
    if (!NT_SUCCESS(Status)) {
	NtUnmapViewOfSection(NtCurrentProcess(), BaseAddress);
	if (Module) {
	    ExFreePool(Module);
	}
    }
    return Status;
}

static inline PCSTR GetNextLine(IN PCSTR Buffer)
{
    while (*Buffer && *Buffer++ != '\n') ;
    return Buffer;
}

/*
 * Returns the pointer to the position of the character after the last '\' in
 * the given buffer. The path is defined as the string from the beginning of
 * the buffer till either the given delimiter or the new line character ('\n').
 * For instance, for "drivers/intel/e1000e.ko:" we will return the start of
 * "e1000e.ko" and length 9.
 */
static inline PCSTR GetModuleBaseName(IN PCSTR Buffer,
				      OUT ULONG *NameLength, /* includes ".ko" */
				      IN CHAR Delimiter)
{
    CHAR Delimiters[] = { '/', Delimiter, '\n', '\0' };
    while (TRUE) {
	PCSTR NextToken = strpbrk(Buffer, Delimiters);
	if (!NextToken) {
	    *NameLength = strlen(Buffer);
	    return Buffer;
	}
	if (*NextToken == '/') {
	    Buffer = NextToken + 1;
	} else {
	    assert(NextToken > Buffer);
	    *NameLength = NextToken - Buffer;
	    assert(*Buffer);
	    assert(*Buffer != '\n');
	    assert(*Buffer != '/');
	    assert(*Buffer != Delimiter);
	    return Buffer;
	}
    }
}

/* Same as GetModuleBaseNameW, but Delimiter is NUL, and Buffer is assume to
 * be NUL terminated. The path separator is also assumed to be '\\'. */
static inline PWSTR GetModuleBaseNameW(IN PWSTR Buffer)
{
    while (*Buffer) {
	PWSTR NextToken = wcspbrk(Buffer, L"\\");
	if (!NextToken) {
	    return Buffer;
	}
	Buffer = NextToken + 1;
    }
    /* We should never get here. */
    assert(FALSE);
    return NULL;
}

static NTSTATUS LnxDrvLoadModuleWithDependency(IN PWSTR ModulePath,
					       IN OPTIONAL PKEVENT Event)
{
    /* Parse the modules.dep file to load its dependencies, before loading the given module. */
    if (LnxDrvModulesDepSize) {
	for (PCSTR Buffer = LnxDrvModulesDep;
	     Buffer < &LnxDrvModulesDep[LnxDrvModulesDepSize] && *Buffer;) {
	    ULONG BaseNameLength = 0;
	    Buffer = GetModuleBaseName(Buffer, &BaseNameLength, ':');
	    if (!Buffer || !*Buffer) {
		break;
	    }
	    WCHAR NameBuffer[256];
	    _snwprintf(NameBuffer, ARRAYSIZE(NameBuffer), L"%.*hs",
		       BaseNameLength, Buffer);
	    /* Make sure we are looking at the entry for this module */
	    if (wcscmp(NameBuffer, GetModuleBaseNameW(ModulePath))) {
		Buffer = GetNextLine(Buffer);
		continue;
	    }
	    _snwprintf(NameBuffer, ARRAYSIZE(NameBuffer), L"\\??\\BootModules\\%.*hs",
		       BaseNameLength, Buffer);

	    /* Skip the basename as well as the ':', and optionally the ' ' after it */
	    Buffer += BaseNameLength + 1;
	    if (*Buffer == ' ') {
		Buffer++;
	    }
	    /* For each module listed in the module dependency list, load it */
	    while (*Buffer && *Buffer != '\n') {
		Buffer = GetModuleBaseName(Buffer, &BaseNameLength, ' ');
		if (!*Buffer || !BaseNameLength) {
		    break;
		}
		/* For now we will hard-code the module search path */
		_snwprintf(NameBuffer, ARRAYSIZE(NameBuffer), L"\\??\\BootModules\\%.*hs",
			   BaseNameLength, Buffer);
		NTSTATUS Status = LnxDrvLoadModuleWithDependency(NameBuffer, Event);
		if (!NT_SUCCESS(Status)) {
		    return Status;
		}
		Buffer += BaseNameLength;
		if (*Buffer == ' ') {
		    Buffer++;
		}
	    }
	    if (*Buffer) {
		Buffer++;
	    }
	}
    }
    return LnxDrvLoadModule(ModulePath, Event);
}

FORCEINLINE BOOLEAN IsHexDigit(IN CHAR Digit)
{
    if (isdigit(Digit)) {
	return TRUE;
    }
    return Digit >= 'A' && Digit <= 'F';
}

/**
 * @brief Matches a fully specified string against a pattern containing wildcards.
 *
 * @param Pattern The wildcard pattern (* = any hex string, ? = '0' or '1').
 * @param Expression The fully specified string to test.
 * @return BOOLEAN TRUE if it matches, FALSE otherwise.
 */
BOOLEAN IsPatternMatch(IN PCSTR Pattern,
		       IN PCSTR Expression)
{
    PCSTR CurrentPattern = Pattern;
    PCSTR CurrentExpression = Expression;

    while (*CurrentExpression != '\0') {
        if (*CurrentPattern == '?') {
	    // Handle '?' wildcard: Must match exactly '0' or '1'
            if (*CurrentExpression == '0' || *CurrentExpression == '1') {
                CurrentPattern++;
                CurrentExpression++;
                continue;
            }
        } else if (*CurrentPattern == '*') {
	    // Handle '*' wildcard: Matches any string of hex digit. The hex digit
	    // string must be upper case.
            while (IsHexDigit(*CurrentExpression)) {
                CurrentExpression++;
            }
	    CurrentPattern++;
	    continue;
        } else if (*CurrentPattern == *CurrentExpression) {
	    // Handle exact character match
            CurrentPattern++;
            CurrentExpression++;
            continue;
        }

        // No match possible
        return FALSE;
    }

    // Eat up any trailing '*' in the pattern
    while (*CurrentPattern == '*') {
        CurrentPattern++;
    }

    // If we consumed the entire pattern, it's a match. The pattern can end in space.
    return *CurrentPattern == '\0' || *CurrentPattern == ' ';
}

static NTSTATUS LnxRequestModule(IN PCSTR AliasPath,
				 IN PVOID Event,
				 IN BOOLEAN Wait)
{
    for (PCSTR Buffer = LnxDrvModulesAlias;
	 Buffer < &LnxDrvModulesAlias[LnxDrvModulesAliasSize] && *Buffer;
	 Buffer = GetNextLine(Buffer)) {
	PCSTR AliasPrefix = "alias ";
	if (strncmp(Buffer, AliasPrefix, strlen(AliasPrefix))) {
	    continue;
	}
	Buffer += strlen(AliasPrefix);

	if (!IsPatternMatch(Buffer, AliasPath)) {
	    continue;
	}

	/* Skip all the way to module base name */
	while (*Buffer && *Buffer++ != ' ') ;
	CHAR BaseNameHyphen[128] = {};
	ULONG BaseNameLength = 0;
	while (Buffer[BaseNameLength] && Buffer[BaseNameLength] != '\n') {
	    if (Buffer[BaseNameLength] != '_') {
		BaseNameHyphen[BaseNameLength] = Buffer[BaseNameLength];
	    } else {
		BaseNameHyphen[BaseNameLength] = '-';
	    }
	    BaseNameLength++;
	    if (BaseNameLength >= sizeof(BaseNameHyphen)) {
		break;
	    }
	}

	/* For now we will hard-code the module search path */
	WCHAR ModuleToLoad[512];
	_snwprintf(ModuleToLoad, ARRAYSIZE(ModuleToLoad),
		   L"\\??\\BootModules\\%hs.ko", BaseNameHyphen);
	NTSTATUS Status = LnxDrvLoadModuleWithDependency(ModuleToLoad, Event);
	if (!NT_SUCCESS(Status)) {
	    /* Try the module file name without hyphen conversion */
	    _snwprintf(ModuleToLoad, ARRAYSIZE(ModuleToLoad),
		       L"\\??\\BootModules\\%.*hs.ko",
		       BaseNameLength, Buffer);
	    return LnxDrvLoadModuleWithDependency(ModuleToLoad, Event);
	} else {
	    return STATUS_SUCCESS;
	}
    }
    return STATUS_NOT_FOUND;
}

static NTSTATUS LnxRequestFirmware(IN PCSTR Name,
				   OUT PVOID *Data,
				   OUT SIZE_T *Size)
{
    ULONG NameLength;
    Name = GetModuleBaseName(Name, &NameLength, '\\');
    WCHAR PathBuffer[512] = {};
    /* For now we will hard-code the firmware search path */
    _snwprintf(PathBuffer, ARRAYSIZE(PathBuffer), L"\\??\\BootModules\\%hs", Name);
    SIZE_T ViewSize = 0;
    return LnxDrvMapFileSection(PathBuffer, Data, &ViewSize, Size);
}

static VOID LnxReleaseFirmware(IN PCVOID Data)
{
    if (Data) {
	NtUnmapViewOfSection(NtCurrentProcess(), (PVOID)Data);
    }
}

/* TSC frequency is in unit of MHz (ie. the value by which TSC increments in one microsecond). */
static ULONG64 LnxGetTscFrequencyInMHz()
{
    return ((KUSER_SHARED_DATA *)(ULONG_PTR)USER_SHARED_DATA)->TscFrequencyInMHz;
}

static ULONG64 LnxGetSystemTime()
{
    LARGE_INTEGER CurrentTime = {};
    KeQuerySystemTime(&CurrentTime);
    return CurrentTime.QuadPart;
}

static KDEFERRED_ROUTINE LnxGlobalTimerCallback;
static NTAPI VOID LnxGlobalTimerCallback(IN PKDPC Dpc,
					 IN PVOID DeferredContext,
					 IN PVOID SystemArgument1,
					 IN OPTIONAL PVOID SystemArgument2)
{
    VOID (MS_ABI *Callback)(PVOID) = SystemArgument1;
    Callback(SystemArgument2);
}

static VOID LnxSetGlobalTimer(IN PLARGE_INTEGER DeltaIn100Ns,
			      IN VOID (MS_ABI *Callback)(PVOID),
			      IN PVOID Context)
{
    LnxDrvGlobalTimerDpc.SystemArgument1 = Callback;
    LnxDrvGlobalTimerDpc.SystemArgument2 = Context;
    /* NT uses a negative value to represent time offset from current time. */
    DeltaIn100Ns->QuadPart = -DeltaIn100Ns->QuadPart;
    KeSetTimer(&LnxDrvGlobalTimer, *DeltaIn100Ns, &LnxDrvGlobalTimerDpc);
}

static NTAPI VOID LnxBugcheckCallback(IN PVOID Buffer,
				      IN ULONG Length)
{
    PLNX_BUGCHECK_CALLBACK Callback = Buffer;
    PKUSER_SHARED_DATA Data = (PVOID)(ULONG_PTR)USER_SHARED_DATA;
    Callback(Data->BugcheckMsg);
}

static VOID LnxRegisterBugcheckCallback(IN PLNX_BUGCHECK_CALLBACK Callback)
{
    PKBUGCHECK_CALLBACK_RECORD Record = ExAllocatePool(NonPagedPool,
						       sizeof(KBUGCHECK_CALLBACK_RECORD));
    if (!Record) {
	return;
    }
    KeInitializeCallbackRecord(Record);
    KeRegisterBugCheckCallback(Record, LnxBugcheckCallback, Callback, 0, NULL);
}

static NTSTATUS LnxRegisterFramebuffer(IN PVOID VirtBase,
				       IN SIZE_T Size,
				       IN ULONG Offset,
				       IN ULONG Width,
				       IN ULONG Height,
				       IN ULONG Pitch,
				       IN UCHAR BitsPerPixel,
				       IN UCHAR BlueIndex,
				       IN UCHAR GreenIndex,
				       IN UCHAR RedIndex,
				       IN BOOLEAN NeedFlush)
{
    return HalRegisterFrameBuffer(VirtBase, Size, Offset, Width, Height, Pitch,
				  BitsPerPixel, BlueIndex, GreenIndex, RedIndex, NeedFlush);
}

static NTSTATUS LnxUnregisterFramebuffer(IN PVOID VirtBase)
{
    return HalUnregisterFrameBuffer(VirtBase);
}

static PVOID LnxGetCurrentTib(VOID)
{
    return NtCurrentTib();
}

static BOOLEAN LnxIsIsrThread(VOID)
{
    return NtCurrentTeb()->Wdm.IsIsrThread;
}

static BOOLEAN LnxIsDpcThread(VOID)
{
    return NtCurrentTeb()->Wdm.IsDpcThread;
}

static VOID __attribute((noreturn)) LnxRaiseStatus(IN NTSTATUS Status)
{
    RtlRaiseStatus(Status);
}

static LNX_DRV_IMPORT_TABLE LnxDrvImportTable = {
    .DbgPrint = LnxDbgPrint,
    .AllocatePhysicalMemory = LnxAllocatePhysicalMemory,
    .FreePhysicalMemory = LnxFreePhysicalMemory,
    .MapPhysicalMemory = LnxMapPhysicalMemory,
    .MapIoSpace = LnxMapIoSpace,
    .UnmapIoSpace = LnxUnmapIoSpace,
    .ReserveVirtualMemory = LnxReserveVirtualMemory,
    .CommitVirtualMemory = LnxCommitVirtualMemory,
    .FreeVirtualMemory = LnxFreeVirtualMemory,
    .AllocatePool = LnxAllocatePool,
    .FreePool = LnxFreePool,
    .GetSystemRamInfo = LnxGetSystemRamInfo,
    .InitializeSoftirqDpc = LnxInitializeSoftirqDpc,
    .QueueSoftirqDpc = LnxQueueSoftirqDpc,
    .AllocateEvent = LnxAllocateEvent,
    .FreeEvent = LnxFreeEvent,
    .SetEvent = LnxSetEvent,
    .ClearEvent = LnxClearEvent,
    .WaitForSingleObject = LnxWaitForSingleObject,
    .AllocateWorkItem = LnxAllocateWorkItem,
    .FreeWorkItem = LnxFreeWorkItem,
    .GetWorkItemExtension = LnxGetWorkItemExtension,
    .QueueWorkItem = LnxQueueWorkItem,
    .ConnectInterrupt = LnxConnectInterrupt,
    .DisconnectInterrupt = LnxDisconnectInterrupt,
    .CreateDevice = LnxCreateDevice,
    .GetDeviceExtension = LnxGetDeviceExtension,
    .AttachDevice = LnxAttachDevice,
    .DeleteDevice = LnxDeleteDevice,
    .GetDeviceSlotAddress = LnxGetDeviceSlotAddress,
    .ReadPciConfig = LnxReadPciConfig,
    .WritePciConfig = LnxWritePciConfig,
#if defined(__i386__) || defined (__x86_64__)
    .ReadIoPort8 = LnxReadIoPort8,
    .ReadIoPort16 = LnxReadIoPort16,
    .ReadIoPort32 = LnxReadIoPort32,
    .WriteIoPort8 = LnxWriteIoPort8,
    .WriteIoPort16 = LnxWriteIoPort16,
    .WriteIoPort32 = LnxWriteIoPort32,
#endif
    .SetFileExtension = LnxSetFileExtension,
    .GetFileExtension = LnxGetFileExtension,
    .GetFileName = LnxGetFileName,
    .IsFileReadable = LnxIsFileReadable,
    .IsFileWritable = LnxIsIsFileWritable,
    .ForwardIrp = LnxForwardIrp,
    .CompleteIrp = LnxCompleteIrp,
    .GetIrpDriverContext = LnxGetIrpDriverContext,
    .SetIrpDriverContext = LnxSetIrpDriverContext,
    .IrpGetRequestBuffer = LnxIrpGetRequestBuffer,
    .IrpGetRequestLength = LnxIrpGetRequestLength,
    .RegisterModule = LnxRegisterModule,
    .RequestModule = LnxRequestModule,
    .RequestFirmware = LnxRequestFirmware,
    .ReleaseFirmware = LnxReleaseFirmware,
    .GetTscFrequencyInMHz = LnxGetTscFrequencyInMHz,
    .GetSystemTime = LnxGetSystemTime,
    .SetGlobalTimer = LnxSetGlobalTimer,
    .RegisterBugcheckCallback = LnxRegisterBugcheckCallback,
    .RegisterFramebuffer = LnxRegisterFramebuffer,
    .UnregisterFramebuffer = LnxUnregisterFramebuffer,
    .GetCurrentTib = LnxGetCurrentTib,
    .IsIsrThread = LnxIsIsrThread,
    .IsDpcThread = LnxIsDpcThread,
    .RaiseStatus = LnxRaiseStatus
};

static NTSTATUS LnxDrvGetPciClassCode(IN PDEVICE_OBJECT PhysicalDeviceObject,
				      OUT ULONG *BaseClass,
				      OUT ULONG *SubClass,
				      OUT ULONG *ProgIf)
{
    ULONG ResultLength = 0;
    WCHAR Buffer[256] = {};
    PWCHAR CompatibleIDs = Buffer;
    BOOLEAN FreeBuffer = FALSE;
    NTSTATUS Status = IoGetDeviceProperty(PhysicalDeviceObject,
					  DevicePropertyCompatibleIDs,
					  sizeof(Buffer),
					  CompatibleIDs,
					  &ResultLength);
    if (Status == STATUS_BUFFER_TOO_SMALL) {
	CompatibleIDs = ExAllocatePool(NonPagedPool, ResultLength);
	if (!CompatibleIDs) {
	    return STATUS_INSUFFICIENT_RESOURCES;
	}
	FreeBuffer = TRUE;
	Status = IoGetDeviceProperty(PhysicalDeviceObject,
				     DevicePropertyCompatibleIDs,
				     ResultLength,
				     CompatibleIDs,
				     &ResultLength);
    }
    if (!NT_SUCCESS(Status)) {
	goto out;
    }

    Status = STATUS_NOT_FOUND;
    for (PWSTR CompatibleID = CompatibleIDs; *CompatibleID;
	 CompatibleID += wcslen(CompatibleID) + 1) {
	PWSTR FoundStr = wcsstr(CompatibleID, L"CC_");
	if (!FoundStr) {
	    continue;
	}
	FoundStr += 3;		/* Skip L"CC_" */
	UNICODE_STRING ClassCodeStr;
	RtlInitUnicodeString(&ClassCodeStr, FoundStr);
	ULONG Value = 0;
	RtlUnicodeStringToInteger(&ClassCodeStr, 16, &Value);
	Status = STATUS_SUCCESS;
	if (FoundStr[4] == L'\0') {
	    *BaseClass = Value >> 8;
	    *SubClass = Value & 0xff;
	    *ProgIf = 0;
	    /* In this case we will keep looking to see if we have the progif. */
	    continue;
	} else {
	    *BaseClass = Value >> 16;
	    *SubClass = (Value >> 8) & 0xff;
	    *ProgIf = Value & 0xff;
	    break;
	}
    }

out:
    if (FreeBuffer) {
	ExFreePool(CompatibleIDs);
    }
    return Status;
}

static NTAPI NTSTATUS LnxDrvAddDevice(IN PDRIVER_OBJECT DriverObject,
				      IN PDEVICE_OBJECT PhysicalDeviceObject)
{
    if (!LnxDrvExportTable.AddDevice) {
	assert(FALSE);
	return STATUS_INVALID_DEVICE_REQUEST;
    }

    CHAR Buffer[128] = {};
    ULONG ResultLength = 0;
    // Query the Device Instance Path from the PDO
    NTSTATUS Status = IoGetDeviceProperty(PhysicalDeviceObject,
					  DevicePropertyInstancePathAnsi,
					  sizeof(Buffer), Buffer, &ResultLength);
    if (!NT_SUCCESS(Status) && Status != STATUS_BUFFER_TOO_SMALL) {
	return Status;
    }

    PCHAR DeviceInstancePath = Buffer;
    BOOLEAN AllocateBuffer = Status == STATUS_BUFFER_TOO_SMALL;
    if (AllocateBuffer) {
	DeviceInstancePath = ExAllocatePool(NonPagedPool, ResultLength);
	if (!DeviceInstancePath) {
	    return STATUS_INSUFFICIENT_RESOURCES;
	}
	Status = IoGetDeviceProperty(PhysicalDeviceObject,
				     DevicePropertyInstancePathAnsi,
				     ResultLength,
				     DeviceInstancePath,
				     &ResultLength);
	if (!NT_SUCCESS(Status)) {
	    goto out;
	}
    }

    KEVENT Event;
    KeInitializeEvent(&Event, SynchronizationEvent, FALSE);
    /* If we are a PCI device, parse the modules.alias file and load the module for
     * this PCI device. */
    PCSTR EnumPrefix = "PCI\\";
    if (!strncmp(DeviceInstancePath, EnumPrefix, strlen(EnumPrefix))) {
	PCSTR VendorPrefix = "PCI\\VEN_";
	ULONG Vendor = 0;
	RtlCharToInteger(DeviceInstancePath + strlen(VendorPrefix), 16, &Vendor);
	assert(Vendor);
	PCSTR DevicePrefix = "PCI\\VEN_XXXX&DEV_";
	ULONG Device = 0;
	RtlCharToInteger(DeviceInstancePath + strlen(DevicePrefix), 16, &Device);
	assert(Device);
	PCSTR SubsystemPrefix = "PCI\\VEN_XXXX&DEV_XXXX&SUBSYS_";
	ULONG Subsystem = 0;
	RtlCharToInteger(DeviceInstancePath + strlen(SubsystemPrefix), 16, &Subsystem);
	assert(Subsystem);
	USHORT SubsysVendor = Subsystem & 0xFFFF;
	USHORT SubsysDevice = Subsystem >> 16;
	ULONG BaseClass = 0;
	ULONG SubClass = 0;
	ULONG ProgIf = 0;
	Status = LnxDrvGetPciClassCode(PhysicalDeviceObject,
				       &BaseClass, &SubClass, &ProgIf);
	if (!NT_SUCCESS(Status)) {
	    goto out;
	}

	CHAR AliasPath[256];
	snprintf(AliasPath, sizeof(AliasPath),
		 "pci:v%08Xd%08Xsv%08Xsd%08Xbc%02Xsc%02Xi%02X",
		 Vendor, Device, SubsysVendor, SubsysDevice, BaseClass, SubClass, ProgIf);
	Status = LnxRequestModule(AliasPath, &Event, FALSE);
	if (!NT_SUCCESS(Status)) {
	    goto out;
	}
    }

    KeClearEvent(&Event);
    Status = LnxDrvExportTable.AddDevice(DriverObject, &Event,
					 PhysicalDeviceObject,
					 DeviceInstancePath);

out:
    KeClearEvent(&Event);
    if (AllocateBuffer) {
	ExFreePool(DeviceInstancePath);
    }
    return Status;
}

static NTSTATUS LnxDrvCompleteOrPendIrp(IN PIRP Irp,
					IN NTSTATUS Status,
					IN ULONG_PTR Information)
{
    PAGED_CODE();
    if (Status != STATUS_PENDING) {
	Irp->IoStatus.Status = Status;
	Irp->IoStatus.Information = Information;
	if (Irp->Tail.DriverContext[1]) {
	    LnxFreeEvent(Irp->Tail.DriverContext[1]);
	}
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
    } else if (!InterlockedCompareExchangePointer((PVOID)Irp->Tail.DriverContext,
						  IRP_PENDING, NULL)) {
	IoMarkIrpPending(Irp);
	InsertTailList(&LnxDrvPendingIrpList, &Irp->Tail.ListEntry);
    }
    return Status;
}

static NTAPI NTSTATUS LnxDrvDispatchCreate(IN PDEVICE_OBJECT DeviceObject,
					   IN PIRP Irp)
{
    if (!DeviceObject->DriverObject) {
	assert(FALSE);
	return STATUS_DRIVER_INTERNAL_ERROR;
    }
    if (!LnxDrvExportTable.DispatchCreate) {
	return STATUS_NOT_IMPLEMENTED;
    }
    assert(!Irp->Tail.DriverContext[0]);
    assert(!Irp->Tail.DriverContext[1]);
    assert(!Irp->Tail.DriverContext[2]);
    assert(!Irp->Tail.DriverContext[3]);
    Irp->Tail.DriverContext[1] = LnxAllocateEvent(FALSE);
    if (!Irp->Tail.DriverContext[1]) {
	return STATUS_INSUFFICIENT_RESOURCES;
    }
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
    PFILE_OBJECT FileObject = Stack->FileObject;
    assert(FileObject);
    NTSTATUS Status = LnxDrvExportTable.DispatchCreate(Irp, DeviceObject,
						       Irp->Tail.DriverContext[1],
						       FileObject);
    return LnxDrvCompleteOrPendIrp(Irp, Status, 0);
}

static NTAPI NTSTATUS LnxDrvDispatchReadWrite(IN PDEVICE_OBJECT DeviceObject,
					      IN PIRP Irp)
{
    if (!DeviceObject->DriverObject) {
	assert(FALSE);
	return STATUS_DRIVER_INTERNAL_ERROR;
    }
    if (!LnxDrvExportTable.DispatchReadWrite) {
	return STATUS_NOT_IMPLEMENTED;
    }
    assert(!Irp->Tail.DriverContext[0]);
    assert(!Irp->Tail.DriverContext[1]);
    assert(!Irp->Tail.DriverContext[2]);
    assert(!Irp->Tail.DriverContext[3]);
    Irp->Tail.DriverContext[1] = LnxAllocateEvent(FALSE);
    if (!Irp->Tail.DriverContext[1]) {
	return STATUS_INSUFFICIENT_RESOURCES;
    }
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
    PFILE_OBJECT FileObject = Stack->FileObject;
    assert(FileObject);
    LARGE_INTEGER FileOffset = Stack->Parameters.Read.ByteOffset;
    ULONG Length = Stack->Parameters.Read.Length;
    BOOLEAN Write = Stack->MajorFunction == IRP_MJ_WRITE;
    PVOID Buffer = Irp->MdlAddress ?
	MmGetSystemAddressForMdlSafe(Irp->MdlAddress) : Irp->UserBuffer;
    PULONG_PTR PfnDb = Irp->MdlAddress ? Irp->MdlAddress->PfnEntries : NULL;
    ULONG PfnCount = Irp->MdlAddress ? Irp->MdlAddress->PfnCount : 0;
    ULONG ResultLength = 0;
    NTSTATUS Status = LnxDrvExportTable.DispatchReadWrite(Irp, DeviceObject,
							  Irp->Tail.DriverContext[1],
							  FileObject,
							  &FileOffset, Buffer, Length,
							  PfnDb, PfnCount, Write, &ResultLength);
    return LnxDrvCompleteOrPendIrp(Irp, Status, ResultLength);
}

static NTAPI NTSTATUS LnxDrvDispatchCleanup(IN PDEVICE_OBJECT DeviceObject,
					    IN PIRP Irp)
{
    if (!DeviceObject->DriverObject) {
	assert(FALSE);
	return STATUS_DRIVER_INTERNAL_ERROR;
    }
    if (!LnxDrvExportTable.DispatchCleanup) {
	return STATUS_SUCCESS;
    }
    assert(!Irp->Tail.DriverContext[0]);
    assert(!Irp->Tail.DriverContext[1]);
    assert(!Irp->Tail.DriverContext[2]);
    assert(!Irp->Tail.DriverContext[3]);
    Irp->Tail.DriverContext[1] = LnxAllocateEvent(FALSE);
    if (!Irp->Tail.DriverContext[1]) {
	return STATUS_INSUFFICIENT_RESOURCES;
    }
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
    PFILE_OBJECT FileObject = Stack->FileObject;
    assert(FileObject);
    NTSTATUS Status = LnxDrvExportTable.DispatchCleanup(Irp, DeviceObject,
							Irp->Tail.DriverContext[1],
							FileObject);
    return LnxDrvCompleteOrPendIrp(Irp, Status, 0);
}

static ULONG LnxDrvConvertResources(IN PCM_RESOURCE_LIST RawList,
				    IN PCM_RESOURCE_LIST TranslatedList,
				    OUT OPTIONAL PLNXDRV_RESOURCE Resources)
{
    ULONG Count = 0;

    if (!RawList || !TranslatedList)
        return 0;

    PCM_PARTIAL_RESOURCE_LIST RawPartial = &RawList->List[0].PartialResourceList;
    PCM_PARTIAL_RESOURCE_LIST Partial = &TranslatedList->List[0].PartialResourceList;
    ASSERT(RawPartial->Count == Partial->Count);

    for (ULONG i = 0; i < Partial->Count; i++) {
	PCM_PARTIAL_RESOURCE_DESCRIPTOR RawDesc = &RawPartial->PartialDescriptors[i];
        PCM_PARTIAL_RESOURCE_DESCRIPTOR Desc = &Partial->PartialDescriptors[i];
        switch (Desc->Type) {
        case CmResourceTypePort:
	    if (Resources) {
		Resources[Count].Type = LnxResIoPort;
		Resources[Count].IoRange.Start = Desc->Port.Start.QuadPart;
		Resources[Count].IoRange.Length = Desc->Port.Length;
		Resources[Count].IoRange.Index = -1;
	    }
            Count++;
            break;

        case CmResourceTypeMemory:
	    if (Resources) {
		Resources[Count].Type = LnxResMemory;
		Resources[Count].IoRange.Start = Desc->Memory.Start.QuadPart;
		Resources[Count].IoRange.Length = Desc->Memory.Length;
		Resources[Count].IoRange.Index = -1;
	    }
            Count++;
            break;

        case CmResourceTypeInterrupt:
	    if (Resources) {
		Resources[Count].Type = LnxResInterrupt;
		if (Desc->Flags & CM_RESOURCE_INTERRUPT_EXTENDED_MESSAGE) {
		    Resources[Count].Interrupt.Irq = Desc->MessageInterrupt.Translated.Level;
		    Resources[Count].Interrupt.Count = RawDesc->MessageInterrupt.Raw.MessageCount;
		    Resources[Count].Interrupt.Type = LnxDrvInterruptTypeMsiX;
		} else if (Desc->Flags & CM_RESOURCE_INTERRUPT_MESSAGE) {
		    Resources[Count].Interrupt.Irq = Desc->MessageInterrupt.Translated.Level;
		    Resources[Count].Interrupt.Count = RawDesc->MessageInterrupt.Raw.MessageCount;
		    Resources[Count].Interrupt.Type = LnxDrvInterruptTypeMsi;
		} else {
		    Resources[Count].Interrupt.Irq = Desc->Interrupt.Vector;
		    Resources[Count].Interrupt.Count = 1;
		    Resources[Count].Interrupt.Type = LnxDrvInterruptTypeLegacy;
		}
	    }
            Count++;
            break;

        case CmResourceTypeBusNumber:
	    if (Resources) {
		Resources[Count].Type = LnxResBusNumber;
		Resources[Count].BusNumber.Start = Desc->BusNumber.Start;
		Resources[Count].BusNumber.Length = Desc->BusNumber.Length;
	    }
            Count++;
            break;

	case CmResourceTypeDevicePrivate:
	    /* For PCI bus, we retrieve the BAR index of the corresponding IO
	     * resource (which is the IO resource immediately before this one). */
	    if (TranslatedList->List[0].InterfaceType == PCIBus &&
		Desc->DevicePrivate.Data[0] == PciBarIndex && Resources) {
		assert(Count);
		assert(Resources[Count-1].Type == LnxResIoPort ||
		       Resources[Count-1].Type == LnxResMemory);
		Resources[Count-1].IoRange.Index = Desc->DevicePrivate.Data[1];
		/* Note we do not increase the resource count here. Unknown device
		 * private data are ignored. */
	    }
	    break;

        default:
            /* Ignore other resource types */
            break;
        }
    }

    return Count;
}

static NTAPI NTSTATUS LnxDrvDispatchPnp(IN PDEVICE_OBJECT DeviceObject,
					IN PIRP Irp)
{
    if (!DeviceObject->DriverObject) {
	assert(FALSE);
	return STATUS_DRIVER_INTERNAL_ERROR;
    }

    assert(!Irp->Tail.DriverContext[0]);
    assert(!Irp->Tail.DriverContext[1]);
    assert(!Irp->Tail.DriverContext[2]);
    assert(!Irp->Tail.DriverContext[3]);
    Irp->Tail.DriverContext[1] = LnxAllocateEvent(FALSE);
    if (!Irp->Tail.DriverContext[1]) {
	return STATUS_INSUFFICIENT_RESOURCES;
    }
    PIO_STACK_LOCATION IrpStack = IoGetCurrentIrpStackLocation(Irp);
    PCM_RESOURCE_LIST RawList = IrpStack->Parameters.StartDevice.AllocatedResources;
    PCM_RESOURCE_LIST TranslatedList =
	IrpStack->Parameters.StartDevice.AllocatedResourcesTranslated;
    ULONG ResourceCount = LnxDrvConvertResources(RawList, TranslatedList, NULL);
    PLNXDRV_RESOURCE Resources = NULL;
    NTSTATUS Status;
    if (ResourceCount) {
	Resources = ExAllocatePool(NonPagedPool, sizeof(LNXDRV_RESOURCE) * ResourceCount);
	if (!ResourceCount) {
	    Status = STATUS_INSUFFICIENT_RESOURCES;
	    goto out;
	}
	LnxDrvConvertResources(RawList, TranslatedList, Resources);
    }

    switch (IrpStack->MinorFunction) {
    case IRP_MN_START_DEVICE:
	if (LnxDrvExportTable.StartDevice) {
	    Status = LnxDrvExportTable.StartDevice(Irp, DeviceObject,
						   Irp->Tail.DriverContext[1],
						   ResourceCount, Resources);
	} else {
	    assert(FALSE);
	    Status = STATUS_NOT_IMPLEMENTED;
	}
	break;
    default:
	Status = STATUS_NOT_SUPPORTED;
    }

out:
    if (Resources) {
	ExFreePool(Resources);
    }
    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

static NTAPI VOID LnxInitializeWorkerRoutine(IN PVOID Unused,
					     IN PVOID Context,
					     IN PIO_WORKITEM WorkItem)
{
    PDRIVER_OBJECT DriverObject = Context;
    KEVENT Event;
    KeInitializeEvent(&Event, SynchronizationEvent, FALSE);
    assert(LnxDrvExportTable.InitializeDriver);
    NTSTATUS Status = LnxDrvExportTable.InitializeDriver(DriverObject, &Event);
    if (!NT_SUCCESS(Status)) {
	goto out;
    }
out:
    KeClearEvent(&Event);
    IoFreeWorkItem(WorkItem);
    if (!NT_SUCCESS(Status)) {
	RtlRaiseStatus(Status);
    }
}

static NTSTATUS LnxDrvQueryServiceKey(IN PUNICODE_STRING RegistryPath,
				      IN ULONG ValueType,
				      IN PWSTR ValueNameString,
				      OUT PKEY_VALUE_PARTIAL_INFORMATION *pValueInfo)
{
    /* Open service key (RegistryPath) */
    OBJECT_ATTRIBUTES ObjectAttributes;
    InitializeObjectAttributes(&ObjectAttributes, RegistryPath,
			       OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE ServiceKeyHandle = NULL;
    NTSTATUS Status = NtOpenKey(&ServiceKeyHandle, KEY_READ, &ObjectAttributes);

    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    /* Open Parameters subkey */
    UNICODE_STRING ParametersKeyName;
    RtlInitUnicodeString(&ParametersKeyName, L"Parameters");

    InitializeObjectAttributes(&ObjectAttributes, &ParametersKeyName,
			       OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, ServiceKeyHandle,
			       NULL);

    HANDLE ParametersKeyHandle = NULL;
    Status = NtOpenKey(&ParametersKeyHandle, KEY_READ, &ObjectAttributes);

    NtClose(ServiceKeyHandle);

    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    UNICODE_STRING ValueName;
    RtlInitUnicodeString(&ValueName, ValueNameString);

    ULONG ResultLength;
    Status = NtQueryValueKey(ParametersKeyHandle, &ValueName, KeyValuePartialInformation,
			     NULL, 0, &ResultLength);

    if (Status != STATUS_BUFFER_TOO_SMALL && Status != STATUS_BUFFER_OVERFLOW) {
	NtClose(ParametersKeyHandle);
	return Status;
    }

    PKEY_VALUE_PARTIAL_INFORMATION ValueInfo = ExAllocatePoolWithTag(NonPagedPool,
								     ResultLength,
								     LNXDRV_TAG);

    if (ValueInfo == NULL) {
	NtClose(ParametersKeyHandle);
	return STATUS_INSUFFICIENT_RESOURCES;
    }

    Status = NtQueryValueKey(ParametersKeyHandle, &ValueName, KeyValuePartialInformation,
			     ValueInfo, ResultLength, &ResultLength);

    NtClose(ParametersKeyHandle);

    if (!NT_SUCCESS(Status) || ValueInfo->Type != ValueType) {
	ExFreePool(ValueInfo);
	return STATUS_OBJECT_NAME_NOT_FOUND;
    }

    *pValueInfo = ValueInfo;
    return STATUS_SUCCESS;
}

static NTSTATUS LnxDrvLoadImage(IN PWSTR ImagePath,
				OUT PVOID *pImageBase,
				OUT PVOID *pLoadedBase,
				OUT PVOID *pTransferAddress)
{
    HANDLE FileHandle;
    NTSTATUS Status = LnxDrvOpenFile(ImagePath, FILE_EXECUTE, &FileHandle);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    /* Create SEC_IMAGE section */
    HANDLE SectionHandle = NULL;
    Status = NtCreateSection(&SectionHandle, SECTION_MAP_EXECUTE | SECTION_MAP_READ, NULL,
			     NULL, PAGE_EXECUTE, SEC_IMAGE, FileHandle);

    NtClose(FileHandle);

    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    /* Query image base address and transfer address */
    SECTION_BASIC_INFORMATION SectionInfo;
    Status = NtQuerySection(SectionHandle, SectionBasicInformation, &SectionInfo,
			    sizeof(SectionInfo), NULL);
    if (!NT_SUCCESS(Status)) {
	NtClose(SectionHandle);
	return Status;
    }
    SECTION_IMAGE_INFORMATION ImageInfo;
    Status = NtQuerySection(SectionHandle, SectionImageInformation, &ImageInfo,
			    sizeof(ImageInfo), NULL);
    if (!NT_SUCCESS(Status)) {
	NtClose(SectionHandle);
	return Status;
    }

    /* Map into driver address space */
    PVOID ImageBase = NULL;
    SIZE_T ViewSize = 0;
    Status = NtMapViewOfSection(SectionHandle, NtCurrentProcess(), &ImageBase, 0, 0, NULL,
				&ViewSize, ViewShare, 0, PAGE_EXECUTE_READ);
    NtClose(SectionHandle);

    UNICODE_STRING ImagePathU;
    RtlInitUnicodeString(&ImagePathU, ImagePath);
    Status = LdrRegisterElfModule(ImageBase, ImageInfo.TransferAddress,
				  ViewSize, &ImagePathU, NULL);

    if (!NT_SUCCESS(Status)) {
	NtUnmapViewOfSection(NtCurrentProcess(), ImageBase);
	return Status;
    }

    *pImageBase = SectionInfo.BaseAddress;
    *pLoadedBase = ImageBase;
    *pTransferAddress = ImageInfo.TransferAddress;
    return STATUS_SUCCESS;
}

typedef struct _LNX_DRV_FB_DAMAGE_INFO {
    IO_WORKITEM WorkItem;
    PVOID VirtBase;
    ULONG StartWidth;
    ULONG StartHeight;
    ULONG EndWidth;
    ULONG EndHeight;
} LNX_DRV_FB_DAMAGE_INFO, *PLNX_DRV_FB_DAMAGE_INFO;

static NTAPI VOID LnxHandleFbDamageWorker(IN PDEVICE_OBJECT Unused,
					  IN PVOID Context)
{
    PLNX_DRV_FB_DAMAGE_INFO Info = Context;
    KEVENT Event;
    KeInitializeEvent(&Event, SynchronizationEvent, FALSE);
    LnxDrvExportTable.HandleFrameBufferDamage(&Event, Info->VirtBase,
					      Info->StartWidth, Info->StartHeight,
					      Info->EndWidth, Info->EndHeight);
    KeClearEvent(&Event);
    ExFreePool(Info);
}

static NTAPI VOID LnxDrvHandleFrameBufferDamage(IN PVOID VirtBase,
						IN ULONG StartWidth,
						IN ULONG StartHeight,
						IN ULONG EndWidth,
						IN ULONG EndHeight)
{
    PLNX_DRV_FB_DAMAGE_INFO Info = ExAllocatePool(NonPagedPool, sizeof(*Info));
    if (!Info) {
	return;
    }
    IoInitializeWorkItem(NULL, &Info->WorkItem);
    Info->VirtBase = VirtBase;
    Info->StartWidth = StartWidth;
    Info->StartHeight = StartHeight;
    Info->EndWidth = EndWidth;
    Info->EndHeight = EndHeight;
    IoQueueWorkItem(&Info->WorkItem, LnxHandleFbDamageWorker, DelayedWorkQueue, Info);
}

NTAPI NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject,
			   IN PUNICODE_STRING RegistryPath)
{
    InitializeListHead(&LnxDrvPendingIrpList);
    InitializeListHead(&LnxDrvLoadedModules);
    RtlInitializeSListHead(&LnxDrvCompletionIrpList);
    KeInitializeTimer(&LnxDrvGlobalTimer);
    KeInitializeDpc(&LnxDrvGlobalTimerDpc, LnxGlobalTimerCallback, &LnxDrvGlobalTimer);
    IoInitializeWorkItem(NULL, &LnxDrvIrpCompletionWorkItem);
    HalRegisterFrameBufferDamageHandler(LnxDrvHandleFrameBufferDamage);

    /* Try creating the object directory \Device\LnxDrv\. This may have already
     * been created by another instance of us, so we ignore any error here. */
    UNICODE_STRING ObjDir = RTL_CONSTANT_STRING(LNXDRV_DEV_OBJ_PATH);
    OBJECT_ATTRIBUTES ObjAttr;
    InitializeObjectAttributes(&ObjAttr, &ObjDir,
			       OBJ_PERMANENT | OBJ_CASE_INSENSITIVE,
			       NULL, NULL);
    HANDLE DirHandle;
    NtCreateDirectoryObject(&DirHandle, DIRECTORY_ALL_ACCESS, &ObjAttr);

    PKEY_VALUE_PARTIAL_INFORMATION ValueInfo;
    NTSTATUS Status = LnxDrvQueryServiceKey(RegistryPath, REG_SZ,
					    L"DriverExtensionImage", &ValueInfo);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    PVOID ImageBase;
    PVOID LoadedBase;
    PLNX_DRV_ENTRY_POINT EntryPoint;
    Status = LnxDrvLoadImage((PWSTR)ValueInfo->Data,
			     &ImageBase, &LoadedBase, (PVOID)&EntryPoint);
    if (!NT_SUCCESS(Status)) {
	ExFreePool(ValueInfo);
	return Status;
    }

    if (ImageBase != LoadedBase) {
	DPRINT("Error: image %ws cannot be loaded at preferred base %p (loaded at %p)\n",
	       (PWSTR)ValueInfo->Data, ImageBase, LoadedBase);
	ExFreePool(ValueInfo);
	return STATUS_IMAGE_NOT_AT_BASE;
    }
    ExFreePool(ValueInfo);

    /* Reserve the virtual address range for the Linux kernel modules */
    PVOID ModuleStart = (PVOID)MODULES_VADDR;
    SIZE_T RegionSize = MODULES_LEN;
    Status = NtAllocateVirtualMemory(NtCurrentProcess(), &ModuleStart, 0,
				     &RegionSize, MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(Status)) {
	DPRINT("Failed to reserve module vaddr region, status 0x%x\n", Status);
	goto err;
    }

    /* Map the modules.alias and modules.dep files into memory for later use. */
    Status = LnxDrvQueryServiceKey(RegistryPath, REG_SZ,
				   L"ModulesAliasDatabase", &ValueInfo);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }
    Status = LnxDrvMapFileSection((PWSTR)ValueInfo->Data,
				  (PVOID)&LnxDrvModulesAlias, &LnxDrvModulesAliasSize, NULL);
    ExFreePool(ValueInfo);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }
    Status = LnxDrvQueryServiceKey(RegistryPath, REG_SZ,
				   L"ModulesDepDatabase", &ValueInfo);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }
    Status = LnxDrvMapFileSection((PWSTR)ValueInfo->Data,
				  (PVOID)&LnxDrvModulesDep, &LnxDrvModulesDepSize, NULL);
    ExFreePool(ValueInfo);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    /* Call extension entry */
    Status = EntryPoint(&LnxDrvImportTable, &LnxDrvExportTable);

    if (!NT_SUCCESS(Status)) {
	goto err;
    }

    PIO_WORKITEM WorkItem = IoAllocateWorkItem(NULL);
    if (!WorkItem) {
	Status = STATUS_INSUFFICIENT_RESOURCES;
	goto err;
    }
    IoQueueWorkItemEx(WorkItem, LnxInitializeWorkerRoutine, DelayedWorkQueue, DriverObject);

    /* The LNXDRV driver itself does not participate in the NT PNP device mode, so
     * its AddDevice routine is NULL. Note that IRP for the non-PNP device object
     * created by the Linux driver (meaning the device objects created as a response
     * to a kobject uevent, see kobject_uevent_env() in arch/ntos/drivers/core.c.
     * These device objects are distinguished from PnP device objects, which are
     * enumerated by the NT PnP manager and participate in the PnP device tree)
     * will be dispatched to us. IRPs for the PnP device objects are routed to the
     * corresponding PnP driver object (see LnxInitializeDriver below). */
    DriverObject->MajorFunction[IRP_MJ_CREATE] = LnxDrvDispatchCreate;
    DriverObject->MajorFunction[IRP_MJ_READ] = LnxDrvDispatchReadWrite;
    DriverObject->MajorFunction[IRP_MJ_WRITE] = LnxDrvDispatchReadWrite;
    DriverObject->MajorFunction[IRP_MJ_CLEANUP] = LnxDrvDispatchCleanup;

    return STATUS_SUCCESS;

err:
    NtUnmapViewOfSection(NtCurrentProcess(), LoadedBase);
    return Status;
}

NTSTATUS NTAPI LnxInitializeDriver(IN PDRIVER_OBJECT DriverObject,
				   IN PUNICODE_STRING RegistryPath)
{
    /* Query the service key and load the non-PnP Linux driver modules. For PnP
     * devices, the Linux driver modules are loaded in the AddDevice routine. */
    PKEY_VALUE_PARTIAL_INFORMATION ValueInfo;
    NTSTATUS Status = LnxDrvQueryServiceKey(RegistryPath, REG_MULTI_SZ,
					    L"Modules", &ValueInfo);
    if (NT_SUCCESS(Status)) {
	for (PWSTR Module = (PWSTR)ValueInfo->Data; *Module; Module += wcslen(Module) + 1) {
	    Status = LnxDrvLoadModuleWithDependency(Module, NULL);
	    if (!NT_SUCCESS(Status)) {
		return Status;
	    }
	}
    }

    /* Set the AddDevice routine for the supplied driver object, so it can
     * participate in the NT PnP device model. */
    DriverObject->AddDevice = LnxDrvAddDevice;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = LnxDrvDispatchCreate;
    DriverObject->MajorFunction[IRP_MJ_READ] = LnxDrvDispatchReadWrite;
    DriverObject->MajorFunction[IRP_MJ_WRITE] = LnxDrvDispatchReadWrite;
    DriverObject->MajorFunction[IRP_MJ_PNP] = LnxDrvDispatchPnp;

    return STATUS_SUCCESS;
}

VOID LnxEnableOnScreenDbgPrint(VOID)
{
    LnxDrvDbgPrintOnScreen = TRUE;
}
