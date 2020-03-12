#include <stdint.h>
#include <printf.h>
#include <sel4/sel4.h>
#include <ldr.h>
#include <rtl.h>
#include <ke.h>

BOOT_ENVIRONMENT BootEnvironment;

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
    for (seL4_Word cap = slots.start; cap < slots.end; cap++) {
	seL4_X86_Page_GetAddress_t addr = seL4_X86_Page_GetAddress(cap);
	DbgPrint("    frame cap = %zd (%zxh) paddr = %p error = %zd\n",
		 cap, cap, addr.paddr, addr.error);
    }
}

static void KiDumpBootInfoAll()
{
    KiDumpBootInfoStruct();
    KiDumpUserImageFramesInfo();
}

void KiInitBootEnvironment(seL4_BootInfo *bootinfo) {
    BootEnvironment.BootInfo = bootinfo;
    BootEnvironment.InitialThreadIpcBuffer = bootinfo->ipcBuffer;
    BootEnvironment.InitialThreadTcb = seL4_CapInitThreadTCB;
}

void KiInitializeSystem(seL4_BootInfo *bootinfo) {
    KiInitBootEnvironment(bootinfo);
    KiDumpBootInfoAll();
    while (1);
}
