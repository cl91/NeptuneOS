#include <stdint.h>
#include <printf.h>
#include <ntos.h>
#if defined(_M_IX86) || defined(_M_AMD64)
#include <sel4/arch/bootinfo_types.h>
#endif
#include "ki.h"

PCSTR RtlpDbgTraceModuleName = "NTOS";

/* Minimum alignment for TLS across all platforms. */
#define MIN_ALIGN_BYTES 8
#define MIN_ALIGNED __aligned(MIN_ALIGN_BYTES)

#if MIN_ALIGN_BYTES > EX_POOL_SMALLEST_BLOCK
#error "Since the TLS region of system threads are allocated on the ExPool, " \
    "MIN_ALIGN_BYTES must be less than or equal to the ExPool block alignment."
#endif

/* Static TLS for the initial thread of the root task. */
static char KiStaticTlsArea[NTOS_TLS_AREA_SIZE] MIN_ALIGNED;

/* Address for the IPC buffer of the initial thread of the root task. */
__thread seL4_IPCBuffer *__sel4_ipc_buffer;

/* Thread local variable used by libsel4 for printing syscall errors. */
#ifdef CONFIG_KERNEL_INVOCATION_REPORT_ERROR_IPC
__thread char __sel4_print_error;
#endif

/*
 * Define KiSetTlsBase function which sets the value of the TLS base
 * for the current thread. This is only used to set the TLS base pointer
 * for the initial thread of the root task (which is an ELF target).
 * All other system threads (interrupt handler threads of the NTOS root
 * task) and all PE processes have their TLS base set in ps/create.c
 */
#if defined(_M_AMD64) && defined(CONFIG_FSGSBASE_INST)
static inline VOID KiSetTlsBase(ULONG_PTR TlsBase)
{
    __asm__ __volatile__("wrfsbase %0" :: "r"(TlsBase));
}
#elif defined(_M_ARM64)
static inline VOID KiSetTlsBase(ULONG_PTR TlsBase)
{
    __asm__ __volatile__("msr tpidr_el0,%0" :: "r"(TlsBase));
}
#elif defined(CONFIG_SET_TLS_BASE_SELF)
static inline VOID KiSetTlsBase(ULONG_PTR TlsBase)
{
    seL4_SetTLSBase(TlsBase);
}
#else
#error "You must enable SetTLSBase for i386 build"
#endif

extern char __stack_base[];
extern char __stack_top[];
extern char _text_start[];
extern char _text_end[];
extern char _rodata_start[];
extern char _rodata_end[];
extern char _initcpio_start[];
extern char _initcpio_end[];
extern char _data_start[];
extern char _data_end[];
extern char _bss_start[];
extern char _bss_end[];
extern char _tbss_start[];
extern char _tbss_end[];
extern char _tdata_start[];
extern char _tdata_end[];

ULONG KeProcessorCount;
ULONG KeProcessorArchitecture;
ULONG KeProcessorLevel;
ULONG KeProcessorRevision;
ULONG KeFeatureBits;

/*
 * For the initial thread of the NTOS root task the base of the gs/fs
 * segment (on i386/amd64 respectively) is set to the end of the static
 * TLS area minus 8 bytes (to accommodate the TLS base pointer). The
 * machine word at TlsBase[0] must be set to the value of TlsBase itself.
 *
 * GCC implements an optimization where access to TLS variables can be done
 * simply with %gs:offset where offset is the offset of the TLS variable
 * from the *end* of the TLS region (so the offset is always negative).
 * As long as we never take the address of any TLS variables we don't need
 * to set TlsBase[0] to TlsBase. However clang does not seem to implement
 * this optimization. We therefore must always set TlsBase[0] to TlsBase.
 */
static VOID KiInitRootThread(seL4_BootInfo *BootInfo)
{
    MWORD TlsBase = (MWORD)&KiStaticTlsArea[0] + sizeof(KiStaticTlsArea) - MIN_ALIGN_BYTES;
    *(MWORD *)(TlsBase) = TlsBase;
    KiSetTlsBase(TlsBase);
    __sel4_ipc_buffer = BootInfo->ipcBuffer;

    DbgPrint("Initial root thread address space:\n");
    DbgPrint("    _text_start = %p\n", _text_start);
    DbgPrint("    _text_end = %p\n", _text_end);
    DbgPrint("    _rodata_start = %p\n", _rodata_start);
    DbgPrint("    _rodata_end = %p\n", _rodata_end);
    DbgPrint("    _initcpio_start = %p\n", _initcpio_start);
    DbgPrint("    _initcpio_end = %p\n", _initcpio_end);
    DbgPrint("    _data_start = %p\n", _data_start);
    DbgPrint("    _data_end = %p\n", _data_end);
    DbgPrint("    _bss_start = %p\n", _bss_start);
    DbgPrint("    _bss_end = %p\n", _bss_end);
    DbgPrint("    _tbss_start = %p\n", _tbss_start);
    DbgPrint("    _tbss_end = %p\n", _tbss_end);
    DbgPrint("    _tdata_start = %p\n", _tdata_start);
    DbgPrint("    _tdata_end = %p\n", _tdata_end);
    DbgPrint("    __stack_base = %p\n", __stack_base);
    DbgPrint("    __stack_top = %p\n", __stack_top);
    DbgPrint("    static tls area start = %p\n", KiStaticTlsArea);
    DbgPrint("    desired tls base = %p\n", (PVOID) TlsBase);
    DbgPrint("    &__sel4_ipc_buffer = %p\n", &__sel4_ipc_buffer);
    DbgPrint("    __sel4_ipc_buffer = %p\n", __sel4_ipc_buffer);
}

static VOID KiRecordMachineInformation(seL4_BootInfo *BootInfo)
{
    if (!BootInfo->extraLen) {
	return;
    }

    seL4_BootInfoHeader *BootInfoHeader = (PVOID)((MWORD)BootInfo + PAGE_SIZE);
    while ((MWORD)BootInfoHeader < ((MWORD) BootInfo + PAGE_SIZE + BootInfo->extraLen)) {
	switch (BootInfoHeader->id) {
#if defined(_M_IX86) || defined(_M_AMD64)
	case SEL4_BOOTINFO_HEADER_X86_VBE:
	    /* TODO: Record x86 VBE information */
	    break;
	case SEL4_BOOTINFO_HEADER_X86_MBMMAP:
	    /* TODO: Record x86 memory map information */
	    break;
	case SEL4_BOOTINFO_HEADER_X86_ACPI_RSDP:
	    HalAcpiRegisterRsdp((PHAL_ACPI_RSDP)(BootInfoHeader+1));
	    break;
	case SEL4_BOOTINFO_HEADER_X86_FRAMEBUFFER:
	    /* seL4 does not provide us with pixel format information, so we have
	     * to assume BGR. */
	    HalRegisterBootFrameBuffer((PHAL_FRAMEBUFFER_INFO)(BootInfoHeader+1), 0, 1, 2);
	    break;
	case SEL4_BOOTINFO_HEADER_X86_TSC_FREQ:
	    KiX86TscFreqInMHz = *((uint32_t *)(BootInfoHeader+1));
	    break;
#endif
	case SEL4_BOOTINFO_HEADER_FDT:
	    /* TODO: Record FDT information */
	    break;
	case SEL4_BOOTINFO_HEADER_X86_EFI_SYSTBL_PTR:
	    if (BootInfoHeader->len == sizeof(ULONG) + sizeof(seL4_BootInfoHeader)) {
		HalRegisterEfiSystemTablePointer(*(PULONG)(BootInfoHeader+1),
						 sizeof(ULONG));
	    } else {
		assert(BootInfoHeader->len == sizeof(ULONG64) + sizeof(seL4_BootInfoHeader));
		HalRegisterEfiSystemTablePointer(*(PULONG64)(BootInfoHeader+1),
						 sizeof(ULONG64));
	    }
	default:
	    break;
	}
	BootInfoHeader = (PVOID)((MWORD)BootInfoHeader + BootInfoHeader->len);
    }
}

static VOID KiRecordPhysicalMemoryInfo(seL4_BootInfo *BootInfo)
{
    seL4_SlotRegion Untyped = BootInfo->untyped;
    MWORD LowestPage = MAXULONG_PTR;
    MWORD HighestPage = 0;
    MWORD NumPages = 0;

    for (seL4_CPtr Cap = Untyped.start; Cap < Untyped.end; Cap++) {
        seL4_UntypedDesc *Desc = &BootInfo->untypedList[Cap - Untyped.start];
	if (!Desc->isDevice) {
	    if (Desc->sizeBits >= PAGE_LOG2SIZE) {
		NumPages += 1 << (Desc->sizeBits - PAGE_LOG2SIZE);
	    }
	    if (Desc->paddr > HighestPage) {
		HighestPage = Desc->paddr;
	    }
	    if (Desc->paddr < LowestPage) {
		LowestPage = Desc->paddr;
	    }
	}
    }
    MmLowestPhysicalPage = LowestPage;
    MmHighestPhysicalPage = HighestPage;
    MmNumberOfPhysicalPages = NumPages;
}

#ifdef CONFIG_DEBUG_BUILD

static char *KiDumpBootInfoSlotRegion(char *Buffer,
				      size_t Size,
				      seL4_SlotRegion *SlotRegion)
{
    snprintf(Buffer, Size, "slots [0x%zx, 0x%zx) == [%zd, %zd)",
	     SlotRegion->start, SlotRegion->end, SlotRegion->start, SlotRegion->end);
    return Buffer;
}

#if defined(_M_IX86) || defined(_M_AMD64)
static VOID KiDumpBootInfoVbe(seL4_X86_BootInfo_VBE *VbeInfo)
{
    DbgPrint("        vbe signature %c%c%c%c version 0x%x total memory %d*64KB\n",
	     VbeInfo->vbeInfoBlock.signature[0],
	     VbeInfo->vbeInfoBlock.signature[1],
	     VbeInfo->vbeInfoBlock.signature[2],
	     VbeInfo->vbeInfoBlock.signature[3],
	     VbeInfo->vbeInfoBlock.version,
	     VbeInfo->vbeInfoBlock.totalMemory);
    DbgPrint("        oem str paddr 0x%08x vendor str paddr 0x%08x product str paddr 0x%08x rev str paddr 0x%08x\n",
	     VbeInfo->vbeInfoBlock.oemStringPtr,
	     VbeInfo->vbeInfoBlock.oemVendorNamePtr,
	     VbeInfo->vbeInfoBlock.oemProductNamePtr,
	     VbeInfo->vbeInfoBlock.oemProductRevPtr);
    DbgPrint("        %s%s width %d height %d pitch %d bpp %d framebuffer paddr 0x%08x\n",
	     VbeInfo->vbeModeInfoBlock.vbe_common.modeAttr & (1UL << 4) ? "graphics mode" : "text mode",
	     VbeInfo->vbeModeInfoBlock.vbe_common.modeAttr & (1UL << 7) ? " linear framebuffer" : "",
	     VbeInfo->vbeModeInfoBlock.vbe12_part1.xRes,
	     VbeInfo->vbeModeInfoBlock.vbe12_part1.yRes,
	     VbeInfo->vbeModeInfoBlock.vbe_common.bytesPerScanLine,
	     VbeInfo->vbeModeInfoBlock.vbe12_part1.bitsPerPixel,
	     VbeInfo->vbeModeInfoBlock.vbe20.physBasePtr);
}

static VOID KiDumpBootInfoMemMap(seL4_X86_BootInfo_mmap_t *MemMapInfo)
{
    /* TODO */
}

static VOID KiDumpBootInfoFrameBuffer(seL4_X86_BootInfo_fb_t *FbInfo)
{
    DbgPrint("    Framebuffer info:\n");
    DbgPrint("        physical address = 0x%llx\n", FbInfo->PhysicalAddress);
    DbgPrint("        pitch = 0x%x\n", FbInfo->Pitch);
    DbgPrint("        width = %d\n", FbInfo->Width);
    DbgPrint("        height = %d\n", FbInfo->Height);
    DbgPrint("        bpp = %d\n", FbInfo->BitsPerPixel);
    DbgPrint("        type = %d\n", FbInfo->Type);
}
#endif

static VOID KiDumpBootInfoStruct(seL4_BootInfo *BootInfo)
{
    CHAR Buf[64];

    DbgPrint("Bootinfo record:\n");
    DbgPrint("    bootinfo vaddr = %p\n", BootInfo);
    DbgPrint("    extraLen = %zd\n", BootInfo->extraLen);
    DbgPrint("    nodeID = %zd\n", BootInfo->nodeID);
    DbgPrint("    numNodes = %zd\n", BootInfo->numNodes);
    DbgPrint("    numIOPTLevels = %zd\n", BootInfo->numIOPTLevels);
    DbgPrint("    ipcBuffer = %p\n", BootInfo->ipcBuffer);
    DbgPrint("    empty = %s\n",
	     KiDumpBootInfoSlotRegion(Buf, sizeof(Buf), &BootInfo->empty));
    DbgPrint("    sharedFrames = %s\n",
	     KiDumpBootInfoSlotRegion(Buf, sizeof(Buf), &BootInfo->sharedFrames));
    DbgPrint("    userImageFrames = %s\n",
	     KiDumpBootInfoSlotRegion(Buf, sizeof(Buf), &BootInfo->userImageFrames));
    DbgPrint("    userImagePaging = %s\n",
	     KiDumpBootInfoSlotRegion(Buf, sizeof(Buf), &BootInfo->userImagePaging));
    DbgPrint("    ioSpaceCaps = %s\n",
	     KiDumpBootInfoSlotRegion(Buf, sizeof(Buf), &BootInfo->ioSpaceCaps));
    DbgPrint("    extraBIPages = %s\n",
	     KiDumpBootInfoSlotRegion(Buf, sizeof(Buf), &BootInfo->extraBIPages));
    DbgPrint("    initThreadCNodeSizeBits = %zd\n", BootInfo->initThreadCNodeSizeBits);
    DbgPrint("    initThreadDomain = %zd\n", BootInfo->initThreadDomain);
    DbgPrint("    untyped = %s\n",
	     KiDumpBootInfoSlotRegion(Buf, sizeof(Buf), &BootInfo->untyped));

    if (!BootInfo->extraLen) {
	return;
    }

    DbgPrint("Extra bootinfo structures:\n");
    seL4_BootInfoHeader *BootInfoHeader = (PVOID)((MWORD)BootInfo + PAGE_SIZE);
    while ((MWORD)BootInfoHeader < ((MWORD)BootInfo + PAGE_SIZE + BootInfo->extraLen)) {
	switch (BootInfoHeader->id) {
	case SEL4_BOOTINFO_HEADER_PADDING:
	    DbgPrint("    empty bootinfo padding of size 0x%zx\n", BootInfoHeader->len);
	    break;
#if defined(_M_IX86) || defined(_M_AMD64)
	case SEL4_BOOTINFO_HEADER_X86_VBE:
	    DbgPrint("    x86 vbe info of size 0x%zx\n", BootInfoHeader->len);
	    KiDumpBootInfoVbe((seL4_X86_BootInfo_VBE *)(BootInfoHeader+1));
	    break;
	case SEL4_BOOTINFO_HEADER_X86_MBMMAP:
	    DbgPrint("    x86 mem map of size 0x%zx\n", BootInfoHeader->len);
	    KiDumpBootInfoMemMap((seL4_X86_BootInfo_mmap_t *)(BootInfoHeader+1));
	    break;
	case SEL4_BOOTINFO_HEADER_X86_ACPI_RSDP:
	    DbgPrint("    x86 acpi rsdp of size 0x%zx\n", BootInfoHeader->len);
	    HalAcpiDumpRsdp((PHAL_ACPI_RSDP)(BootInfoHeader+1), 8);
	    break;
	case SEL4_BOOTINFO_HEADER_X86_FRAMEBUFFER:
	    DbgPrint("    x86 multiboot2 framebuffer info of size 0x%zx\n",
		     BootInfoHeader->len);
	    KiDumpBootInfoFrameBuffer((seL4_X86_BootInfo_fb_t *)(BootInfoHeader+1));
	    break;
	case SEL4_BOOTINFO_HEADER_X86_TSC_FREQ:
	    DbgPrint("    x86 tsc freq of size 0x%zx\n", BootInfoHeader->len);
	    DbgPrint("        tsc freq is %d MHz\n", KiX86TscFreqInMHz);
	    break;
#endif
	case SEL4_BOOTINFO_HEADER_FDT:
	    DbgPrint("    fdt of size 0x%zx\n", BootInfoHeader->len);
	    break;
	case SEL4_BOOTINFO_HEADER_X86_EFI_SYSTBL_PTR:
	    DbgPrint("    efi system table pointer of size 0x%zx\n", BootInfoHeader->len);
	    if (BootInfoHeader->len == sizeof(ULONG) + sizeof(seL4_BootInfoHeader)) {
		DbgPrint("        efi system table at physical address 0x%x\n",
			 *(PULONG)(BootInfoHeader+1));
	    } else {
		assert(BootInfoHeader->len == sizeof(ULONG64) + sizeof(seL4_BootInfoHeader));
		DbgPrint("        efi system table at physical address 0x%llx\n",
			 *(PULONG64)(BootInfoHeader+1));
	    }
	    break;
	default:
	    DbgPrint("    unknown bootinfo of id %zd and size 0x%zx\n",
		     BootInfoHeader->id, BootInfoHeader->len);
	    break;
	}
	BootInfoHeader = (PVOID)((MWORD)BootInfoHeader + BootInfoHeader->len);
    }
}

static VOID KiDumpUserImageFramesInfo(seL4_BootInfo *BootInfo)
{
    seL4_SlotRegion Slots = BootInfo->userImageFrames;

    DbgPrint("Initial root task user image frames:\n"
	     "    frame cap = [%zd, %zd] ([0x%zx, 0x%zx]) paddr = [%p, %p]\n",
	     Slots.start, Slots.end-1, Slots.start, Slots.end-1,
	     (PVOID) seL4_Page_GetAddress(Slots.start).paddr,
	     (PVOID) (seL4_Page_GetAddress(Slots.end-1).paddr + PAGE_SIZE - 1));
}

static VOID KiDumpUntypedMemoryInfo(seL4_BootInfo *BootInfo)
{
    seL4_SlotRegion Untyped = BootInfo->untyped;

    DbgPrint("Initial root untyped capabilities:\n");
    for (seL4_CPtr Cap = Untyped.start; Cap < Untyped.end; Cap++) {
        seL4_UntypedDesc *Desc = &BootInfo->untypedList[Cap - Untyped.start];
        DbgPrint("    %s cap = %zd (0x%zx) paddr = %p log2(size) = %d\n",
		 Desc->isDevice ? "device untyped" : "untyped",
		 Cap, Cap, (PVOID) Desc->paddr, Desc->sizeBits);
    }
}

static VOID KiDumpBootInfoAll(seL4_BootInfo *BootInfo)
{
    KiDumpBootInfoStruct(BootInfo);
    KiDumpUserImageFramesInfo(BootInfo);
    KiDumpUntypedMemoryInfo(BootInfo);
    DbgPrint("\n");
}

#endif	/* CONFIG_DEBUG_BUILD */

static VOID KiRecordProcessorInformation()
{
#ifdef _M_IX86
    KeProcessorArchitecture = PROCESSOR_ARCHITECTURE_INTEL;
#elif defined(_M_AMD64)
    KeProcessorArchitecture = PROCESSOR_ARCHITECTURE_AMD64;
#elif defined(_M_ARM64)
    KeProcessorArchitecture = PROCESSOR_ARCHITECTURE_ARM;
#else
#error "Unsupported architecture"
#endif
#if defined(_M_IX86) || defined(_M_AMD64)
    /* Call cpuid to fill in other CPU info
     * mode 1 => get extended family id, model id, proc type, family id, model and stepping id */
    int CPUInfo[4];
    __cpuid(CPUInfo, 1);
    KeProcessorLevel = (CPUInfo[0] & 0x0F00);
    KeProcessorLevel >>= 8;
    KeProcessorRevision = (CPUInfo[0] & 0x00F0);
    KeProcessorRevision <<= 4;
    KeProcessorRevision += (CPUInfo[0] & 0x0F00);
    KeProcessorRevision &= 0x0F0F;
    /* TODO: translate various cpuid information into Microsoft Feature Bits.
     * See ReactOS work on this part */
    KeFeatureBits = 0;
#endif
}

#define OS_BANNER	"Neptune OS [Version " VER_PRODUCTVERSION_STRING "]"

VOID KiInitializeSystem(seL4_BootInfo *BootInfo) {
    KiInitRootThread(BootInfo);
    KeProcessorCount = BootInfo->numNodes;
    if (KeProcessorCount == 0) {
	KeProcessorCount = 1;
    }
    KiRecordProcessorInformation();
    KiRecordMachineInformation(BootInfo);

#ifdef CONFIG_DEBUG_BUILD
    seL4_DebugNameThread(NTOS_TCB_CAP, "NTOS Executive");
    KiDumpBootInfoAll(BootInfo);
#endif

    KiRecordPhysicalMemoryInfo(BootInfo);
    ExInitSystemPhase0(BootInfo);
    HalDisplayString(OS_BANNER "    ");
    BUGCHECK_IF_ERR(KiInitExecutiveServices());
    BUGCHECK_IF_ERR(KiInitBugCheck());
    BUGCHECK_IF_ERR(KiInitTimer());
    BUGCHECK_IF_ERR(ExInitSystemPhase1());

#ifdef CONFIG_RUN_TESTS
    KeRunAllTests();
#endif

    KeSetThreadPriority(NTOS_TCB_CAP, SYSTEM_SERVICE_LEVEL);
    /* This should never return. */
    KiDispatchExecutiveServices();
}
