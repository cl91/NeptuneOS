#include <stdint.h>
#include <printf.h>
#include <sel4/sel4.h>
#include <ntsvc.h>

static void KiInitRootThread(seL4_BootInfo *bootinfo)
{
    seL4_SetTLSBase(bootinfo->ipcBuffer);
    __sel4_ipc_buffer = bootinfo->ipcBuffer;
}

static BOOT_ENVIRONMENT BootEnvironment;

PBOOT_ENVIRONMENT KeGetBootEnvironment()
{
    return &BootEnvironment;
}

static char *KiDumpBootInfoSlotRegion(char *buf,
				      size_t size,
				      seL4_SlotRegion *sl)
{
    snprintf(buf, size, "slots [%zxh, %zxh) == [%zd, %zd)",
	     sl->start, sl->end, sl->start, sl->end);
    return buf;
}

static void KiDumpBootInfoStruct()
{
    seL4_BootInfo *bootinfo = KeGetBootEnvironment()->BootInfo;
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

static void KiDumpUserImageFramesInfo()
{
    seL4_SlotRegion slots = KeGetBootEnvironment()->BootInfo->userImageFrames;
    char buf[64];

    DbgPrintFunc();
    for (seL4_CPtr cap = slots.start; cap < slots.end; cap++) {
	seL4_X86_Page_GetAddress_t addr = seL4_X86_Page_GetAddress(cap);
	DbgPrint("    frame cap = %zd (%zxh) paddr = %p error = %zd\n",
		 cap, cap, addr.paddr, addr.error);
    }
}

static void KiDumpUntypedMemoryInfo()
{
    seL4_BootInfo *bootinfo = KeGetBootEnvironment()->BootInfo;
    seL4_SlotRegion untyped = bootinfo->untyped;

    DbgPrintFunc();
    for (seL4_CPtr cap = untyped.start; cap < untyped.end; cap++) {
        seL4_UntypedDesc *desc = &bootinfo->untypedList[cap - untyped.start];
        DbgPrint("    %s cap = %zd (%zxh) paddr = %p log2(size) = %d\n",
		 desc->isDevice ? "device untyped" : "untyped",
		 cap, cap, desc->paddr, desc->sizeBits);
    }
}

static void KiDumpBootInfoAll()
{
    KiDumpBootInfoStruct();
    KiDumpUserImageFramesInfo();
    KiDumpUntypedMemoryInfo();
}

void KiInitBootEnvironment(seL4_BootInfo *bootinfo) {
    BootEnvironment.BootInfo = bootinfo;
    BootEnvironment.InitialThreadIpcBuffer = bootinfo->ipcBuffer;
    BootEnvironment.InitialThreadTcb = seL4_CapInitThreadTCB;
    BootEnvironment.InitialCapSpaceRoot = seL4_CapInitThreadCNode;
    BootEnvironment.InitialCapSpaceStart = bootinfo->empty.start;
    BootEnvironment.InitialCapSpaceEnd = bootinfo->empty.end;
}

void KiInitializeSystem(seL4_BootInfo *bootinfo) {
    KiInitRootThread(bootinfo);
    KiInitBootEnvironment(bootinfo);
    KiDumpBootInfoAll();
    MmInitSystem();
    while (1);
}
