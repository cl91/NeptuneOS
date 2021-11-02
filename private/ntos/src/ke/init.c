#include <stdint.h>
#include <printf.h>
#include <ntos.h>
#include <thread.h>
#include <sel4/arch/bootinfo_types.h>
#include "ki.h"

/* Minimum alignment for TLS across all platforms. */
#define MIN_ALIGN_BYTES 16
#define MIN_ALIGNED __aligned(MIN_ALIGN_BYTES)

/* Static TLS for the initial thread of the root task. */
static char STATIC_TLS_AREA[256] MIN_ALIGNED;

/* Address for the IPC buffer of the initial thread of the root task. */
__thread seL4_IPCBuffer *__sel4_ipc_buffer;

/* Thread local variable used by libsel4 for printing syscall errors. */
#ifdef CONFIG_KERNEL_INVOCATION_REPORT_ERROR_IPC
__thread char __sel4_print_error;
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

/* tls_base[0-sizeof(uintptr_t)] must be a pointer to tls_base
 *
 * For GNU systems the base of gs segment (on i386) is set to
 * tls_base. Access to TLS variables can then be done simply
 * with %gs:-offset. However for some reason clang does not
 * implement this (or need some kind of compiler flag to enable).
 */
static void KiInitRootThread(seL4_BootInfo *bootinfo)
{
    uintptr_t tls_base = (uintptr_t ) &STATIC_TLS_AREA[0]
	+ sizeof(STATIC_TLS_AREA) - MIN_ALIGN_BYTES;
    uintptr_t *tls_ptr = (uintptr_t *)(tls_base);
    *tls_ptr = tls_base;
    sel4runtime_set_tls_base(tls_base);
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
    DbgPrint("    desired tls base = %p\n", (PVOID) tls_base);
    DbgPrint("    tls base = %p\n", (PVOID) sel4runtime_get_tls_base());
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

static void KiDumpBootInfoAll(seL4_BootInfo *bootinfo)
{
    KiDumpBootInfoStruct(bootinfo);
    KiDumpUserImageFramesInfo(bootinfo);
    KiDumpUntypedMemoryInfo(bootinfo);
    DbgPrint("\n");
}

void KiInitializeSystem(seL4_BootInfo *bootinfo) {
    KiInitRootThread(bootinfo);

#ifdef CONFIG_DEBUG_BUILD
    seL4_DebugNameThread(NTEX_TCB_CAP, "NTOS Executive");
    KiDumpBootInfoAll(bootinfo);
#endif

    ExInitSystemPhase0(bootinfo);
    KiInitVga();
    BUGCHECK_IF_ERR(KiInitExecutiveServices());
    BUGCHECK_IF_ERR(ExInitSystemPhase1());

#ifdef CONFIG_RUN_TESTS
    KeRunAllTests();
#endif

    /* This should never return. */
    KiDispatchExecutiveServices();
}
