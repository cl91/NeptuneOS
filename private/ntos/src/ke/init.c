#include <stdint.h>
#include <printf.h>
#include <ntos.h>
#include <sel4/arch/bootinfo_types.h>
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
static char STATIC_TLS_AREA[NTOS_TLS_AREA_SIZE] MIN_ALIGNED;

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
static inline void KiSetTlsBase(uintptr_t tls_base)
{
    __asm__ __volatile__("wrfsbase %0" :: "r"(tls_base));
}
#elif defined(CONFIG_SET_TLS_BASE_SELF)
static inline void KiSetTlsBase(uintptr_t tls_base)
{
    seL4_SetTLSBase(tls_base);
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
ULONG KeX86TscFreq;

#if __i386__
#define __cpuid(__leaf, __eax, __ebx, __ecx, __edx) \
    __asm("cpuid" : "=a"(__eax), "=b" (__ebx), "=c"(__ecx), "=d"(__edx) \
                  : "0"(__leaf))

#define __cpuid_count(__leaf, __count, __eax, __ebx, __ecx, __edx) \
    __asm("cpuid" : "=a"(__eax), "=b" (__ebx), "=c"(__ecx), "=d"(__edx) \
                  : "0"(__leaf), "2"(__count))
#else
/* x86-64 uses %rbx as the base register, so preserve it. */
#define __cpuid(__leaf, __eax, __ebx, __ecx, __edx) \
    __asm("  xchgq  %%rbx,%q1\n" \
          "  cpuid\n" \
          "  xchgq  %%rbx,%q1" \
        : "=a"(__eax), "=r" (__ebx), "=c"(__ecx), "=d"(__edx) \
        : "0"(__leaf))

#define __cpuid_count(__leaf, __count, __eax, __ebx, __ecx, __edx) \
    __asm("  xchgq  %%rbx,%q1\n" \
          "  cpuid\n" \
          "  xchgq  %%rbx,%q1" \
        : "=a"(__eax), "=r" (__ebx), "=c"(__ecx), "=d"(__edx) \
        : "0"(__leaf), "2"(__count))
#endif

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
static void KiInitRootThread(seL4_BootInfo *bootinfo)
{
    MWORD TlsBase = (MWORD)&STATIC_TLS_AREA[0] + sizeof(STATIC_TLS_AREA) - MIN_ALIGN_BYTES;
    *(MWORD *)(TlsBase) = TlsBase;
    KiSetTlsBase(TlsBase);
    __sel4_ipc_buffer = bootinfo->ipcBuffer;

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
    DbgPrint("    static tls area start = %p\n", STATIC_TLS_AREA);
    DbgPrint("    desired tls base = %p\n", (PVOID) TlsBase);
    DbgPrint("    &__sel4_ipc_buffer = %p\n", &__sel4_ipc_buffer);
    DbgPrint("    __sel4_ipc_buffer = %p\n", __sel4_ipc_buffer);
}

static char *KiDumpBootInfoSlotRegion(char *buf,
				      size_t size,
				      seL4_SlotRegion *sl)
{
    snprintf(buf, size, "slots [0x%zx, 0x%zx) == [%zd, %zd)",
	     sl->start, sl->end, sl->start, sl->end);
    return buf;
}

static void KiDumpBootInfoVbe(seL4_X86_BootInfo_VBE *VbeInfo)
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

static void KiDumpBootInfoMemMap(seL4_X86_BootInfo_mmap_t *MemMapInfo)
{
}

static void KiDumpBootInfoFrameBuffer(seL4_X86_BootInfo_fb_t *FbInfo)
{
}

static void KiDumpBootInfoStruct(seL4_BootInfo *bootinfo)
{
    char buf[64];

    DbgPrint("Bootinfo record:\n");
    DbgPrint("    bootinfo vaddr = %p\n", bootinfo);
    DbgPrint("    extraLen = %zd\n", bootinfo->extraLen);
    DbgPrint("    nodeID = %zd\n", bootinfo->nodeID);
    DbgPrint("    numNodes = %zd\n", bootinfo->numNodes);
    DbgPrint("    numIOPTLevels = %zd\n", bootinfo->numIOPTLevels);
    DbgPrint("    ipcBuffer = %p\n", bootinfo->ipcBuffer);
    DbgPrint("    empty = %s\n", KiDumpBootInfoSlotRegion(buf, sizeof(buf), &bootinfo->empty));
    DbgPrint("    sharedFrames = %s\n", KiDumpBootInfoSlotRegion(buf, sizeof(buf), &bootinfo->sharedFrames));
    DbgPrint("    userImageFrames = %s\n", KiDumpBootInfoSlotRegion(buf, sizeof(buf), &bootinfo->userImageFrames));
    DbgPrint("    userImagePaging = %s\n", KiDumpBootInfoSlotRegion(buf, sizeof(buf), &bootinfo->userImagePaging));
    DbgPrint("    ioSpaceCaps = %s\n", KiDumpBootInfoSlotRegion(buf, sizeof(buf), &bootinfo->ioSpaceCaps));
    DbgPrint("    extraBIPages = %s\n", KiDumpBootInfoSlotRegion(buf, sizeof(buf), &bootinfo->extraBIPages));
    DbgPrint("    initThreadCNodeSizeBits = %zd\n", bootinfo->initThreadCNodeSizeBits);
    DbgPrint("    initThreadDomain = %zd\n", bootinfo->initThreadDomain);
    DbgPrint("    untyped = %s\n", KiDumpBootInfoSlotRegion(buf, sizeof(buf), &bootinfo->untyped));

    if (bootinfo->extraLen) {
	DbgPrint("Extra bootinfo structures:\n");
	seL4_BootInfoHeader *BootInfoHeader = (seL4_BootInfoHeader *)((MWORD) bootinfo + PAGE_SIZE);
	while ((MWORD)BootInfoHeader < ((MWORD) bootinfo + PAGE_SIZE + bootinfo->extraLen)) {
	    switch (BootInfoHeader->id) {
	    case SEL4_BOOTINFO_HEADER_PADDING:
		DbgPrint("    empty bootinfo padding of size 0x%zx\n", BootInfoHeader->len);
		break;
	    case SEL4_BOOTINFO_HEADER_X86_VBE:
		DbgPrint("    x86 vbe info of size 0x%zx\n", BootInfoHeader->len);
		KiDumpBootInfoVbe((seL4_X86_BootInfo_VBE *)BootInfoHeader);
		break;
	    case SEL4_BOOTINFO_HEADER_X86_MBMMAP:
		DbgPrint("    x86 mem map of size 0x%zx\n", BootInfoHeader->len);
		KiDumpBootInfoMemMap((seL4_X86_BootInfo_mmap_t *)BootInfoHeader);
		break;
	    case SEL4_BOOTINFO_HEADER_X86_ACPI_RSDP:
		DbgPrint("    x86 acpi rsdp of size 0x%zx\n", BootInfoHeader->len);
		break;
	    case SEL4_BOOTINFO_HEADER_X86_FRAMEBUFFER:
		DbgPrint("    x86 multiboot2 framebuffer info of size 0x%zx\n", BootInfoHeader->len);
		KiDumpBootInfoFrameBuffer((seL4_X86_BootInfo_fb_t *)BootInfoHeader);
		break;
	    case SEL4_BOOTINFO_HEADER_X86_TSC_FREQ:
		DbgPrint("    x86 tsc freq of size 0x%zx\n", BootInfoHeader->len);
		KeX86TscFreq = *((uint32_t *)BootInfoHeader);
		DbgPrint("    tsc freq is %d MHz\n", KeX86TscFreq);
		break;
	    case SEL4_BOOTINFO_HEADER_FDT:
		DbgPrint("    fdt of size 0x%zx\n", BootInfoHeader->len);
		break;
	    default:
		DbgPrint("    unknown bootinfo of id %zd and size 0x%zx\n", BootInfoHeader->id, BootInfoHeader->len);
		break;
	    }
	    BootInfoHeader = (seL4_BootInfoHeader *)((MWORD)BootInfoHeader + BootInfoHeader->len);
	}
    }
}

static void KiDumpUserImageFramesInfo(seL4_BootInfo *bootinfo)
{
    seL4_SlotRegion slots = bootinfo->userImageFrames;
    char buf[64];

    DbgPrint("Initial root task user image frames:\n"
	     "    frame cap = [%zd, %zd] ([0x%zx, 0x%zx]) paddr = [%p, %p]\n",
	     slots.start, slots.end-1, slots.start, slots.end-1,
	     (PVOID) seL4_X86_Page_GetAddress(slots.start).paddr,
	     (PVOID) (seL4_X86_Page_GetAddress(slots.end-1).paddr + PAGE_SIZE - 1));
}

static void KiDumpUntypedMemoryInfo(seL4_BootInfo *bootinfo)
{
    seL4_SlotRegion untyped = bootinfo->untyped;

    DbgPrint("Initial root untyped capabilities:\n");
    for (seL4_CPtr cap = untyped.start; cap < untyped.end; cap++) {
        seL4_UntypedDesc *desc = &bootinfo->untypedList[cap - untyped.start];
        DbgPrint("    %s cap = %zd (0x%zx) paddr = %p log2(size) = %d\n",
		 desc->isDevice ? "device untyped" : "untyped",
		 cap, cap, (PVOID) desc->paddr, desc->sizeBits);
    }
}

static void KiRecordPhysicalMemoryInfo(seL4_BootInfo *bootinfo)
{
    seL4_SlotRegion untyped = bootinfo->untyped;
    MWORD LowestPage = MAXULONG_PTR;
    MWORD HighestPage = 0;
    MWORD NumPages = 0;

    for (seL4_CPtr cap = untyped.start; cap < untyped.end; cap++) {
        seL4_UntypedDesc *desc = &bootinfo->untypedList[cap - untyped.start];
	if (!desc->isDevice) {
	    if (desc->sizeBits >= PAGE_LOG2SIZE) {
		NumPages += 1 << (desc->sizeBits - PAGE_LOG2SIZE);
	    }
	    if (desc->paddr > HighestPage) {
		HighestPage = desc->paddr;
	    }
	    if (desc->paddr < LowestPage) {
		LowestPage = desc->paddr;
	    }
	}
    }
    MmLowestPhysicalPage = LowestPage;
    MmHighestPhysicalPage = HighestPage;
    MmNumberOfPhysicalPages = NumPages;
}

static void KiDumpBootInfoAll(seL4_BootInfo *bootinfo)
{
    KiDumpBootInfoStruct(bootinfo);
    KiDumpUserImageFramesInfo(bootinfo);
    KiDumpUntypedMemoryInfo(bootinfo);
    DbgPrint("\n");
}

static void KiFillProcessorInformation()
{
    /* Call cpuid to fill in other CPU info
     * mode 1 => get extended family id, model id, proc type, family id, model and stepping id */
    unsigned int eax = 0, ebx = 0, ecx = 0, edx = 0;
    __cpuid(1, eax, ebx, ecx, edx);
    KeProcessorArchitecture = PROCESSOR_ARCHITECTURE_INTEL;
    KeProcessorLevel = (eax & 0x0F00);
    KeProcessorLevel >>= 8;
    KeProcessorRevision = (eax & 0x00F0);
    KeProcessorRevision <<= 4;
    KeProcessorRevision += (eax & 0x0F00);
    KeProcessorRevision &= 0x0F0F;
    /* TODO: translate various cpuid information into Microsoft FeatureBits.
     * See reactos work on this part */
    KeFeatureBits = 0;
}

#define OS_BANNER	"Neptune OS [Version " VER_PRODUCTVERSION_STRING "]"

void KiInitializeSystem(seL4_BootInfo *bootinfo) {
    KiInitRootThread(bootinfo);
    KeProcessorCount = bootinfo->numNodes;
    if (KeProcessorCount == 0) {
	KeProcessorCount = 1;
    }
    KiFillProcessorInformation();

#ifdef CONFIG_DEBUG_BUILD
    seL4_DebugNameThread(NTEX_TCB_CAP, "NTOS Executive");
    KiDumpBootInfoAll(bootinfo);
#endif

    KiRecordPhysicalMemoryInfo(bootinfo);
    ExInitSystemPhase0(bootinfo);
    HalDisplayString(OS_BANNER "    ");
    BUGCHECK_IF_ERR(KiInitExecutiveServices());
    BUGCHECK_IF_ERR(KiInitBugCheck());
    BUGCHECK_IF_ERR(KiInitTimer());
    BUGCHECK_IF_ERR(ExInitSystemPhase1());

#ifdef CONFIG_RUN_TESTS
    KeRunAllTests();
#endif

    /* This should never return. */
    KiDispatchExecutiveServices();
}
