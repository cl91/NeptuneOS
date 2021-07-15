#include <stdint.h>
#include <printf.h>
#include <sel4/sel4.h>
#include <ntos.h>
#include <thread.h>
#include "ki.h"

// Minimum alignment for TLS across all platforms.
#define MIN_ALIGN_BYTES 16
#define MIN_ALIGNED __aligned(MIN_ALIGN_BYTES)

// Static TLS for the initial thread.
static char STATIC_TLS_AREA[256] MIN_ALIGNED = {};

extern char __stack_base[];
extern char __stack_top[];
extern char _text_start[];
extern char _text_end[];
extern char _rodata_start[];
extern char _rodata_end[];
extern char _ntdll_start[];
extern char _ntdll_end[];
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
    uintptr_t tls_base = (uintptr_t ) &STATIC_TLS_AREA[0] + sizeof(STATIC_TLS_AREA) - MIN_ALIGN_BYTES;
    uintptr_t *tls_ptr = (uintptr_t *)(tls_base);
    *tls_ptr = tls_base;
    sel4runtime_set_tls_base(tls_base);
    __sel4_ipc_buffer = bootinfo->ipcBuffer;
#ifdef CONFIG_DEBUG_BUILD
    DbgPrintFunc();
    DbgPrint("    _text_start = %p\n", _text_start);
    DbgPrint("    _text_end = %p\n", _text_end);
    DbgPrint("    _rodata_start = %p\n", _rodata_start);
    DbgPrint("    _rodata_end = %p\n", _rodata_end);
    DbgPrint("    _ntdll_start = %p\n", _ntdll_start);
    DbgPrint("    _ntdll_end = %p\n", _ntdll_end);
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
    DbgPrint("    desired tls base = %p\n", tls_base);
    DbgPrint("    tls base = %p\n", sel4runtime_get_tls_base());
    DbgPrint("    &__sel4_ipc_buffer = %p\n", &__sel4_ipc_buffer);
    DbgPrint("    __sel4_ipc_buffer = %p\n", __sel4_ipc_buffer);
#endif
}

static char *KiDumpBootInfoSlotRegion(char *buf,
				      size_t size,
				      seL4_SlotRegion *sl)
{
    snprintf(buf, size, "slots [%zxh, %zxh) == [%zd, %zd)",
	     sl->start, sl->end, sl->start, sl->end);
    return buf;
}

static void KiDumpBootInfoStruct(seL4_BootInfo *bootinfo)
{
    char buf[64];

    DbgPrintFunc();
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
}

static void KiDumpUserImageFramesInfo(seL4_BootInfo *bootinfo)
{
    seL4_SlotRegion slots = bootinfo->userImageFrames;
    char buf[64];

    DbgPrintFunc();
    for (seL4_CPtr cap = slots.start; cap < slots.end; cap++) {
	seL4_X86_Page_GetAddress_t addr = seL4_X86_Page_GetAddress(cap);
	DbgPrint("    frame cap = %zd (%zxh) paddr = %p error = %zd\n",
		 cap, cap, addr.paddr, addr.error);
    }
}

static void KiDumpUntypedMemoryInfo(seL4_BootInfo *bootinfo)
{
    seL4_SlotRegion untyped = bootinfo->untyped;

    DbgPrintFunc();
    for (seL4_CPtr cap = untyped.start; cap < untyped.end; cap++) {
        seL4_UntypedDesc *desc = &bootinfo->untypedList[cap - untyped.start];
        DbgPrint("    %s cap = %zd (%zxh) paddr = %p log2(size) = %d\n",
		 desc->isDevice ? "device untyped" : "untyped",
		 cap, cap, desc->paddr, desc->sizeBits);
    }
}

static void KiDumpBootInfoAll(seL4_BootInfo *bootinfo)
{
    KiDumpBootInfoStruct(bootinfo);
    KiDumpUserImageFramesInfo(bootinfo);
    KiDumpUntypedMemoryInfo(bootinfo);
}

void KiInitializeSystem(seL4_BootInfo *bootinfo) {
    KiInitRootThread(bootinfo);
    seL4_TCB_SetSpace(seL4_CapInitThreadTCB, 0, seL4_CapInitThreadCNode, 0, seL4_CapInitThreadVSpace, 0);
#ifdef CONFIG_DEBUG_BUILD
    KiDumpBootInfoAll(bootinfo);
#endif
    BUGCHECK_IF_ERR(ExInitSystem(bootinfo));
    KiInitVga();
    BUGCHECK_IF_ERR(LdrLoadBootModules());
#ifdef CONFIG_RUN_TESTS
    KeRunAllTests();
#endif

    while (1);
}
