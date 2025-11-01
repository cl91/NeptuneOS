#include "halp.h"

typedef struct _CB_TABLE_HEADER {
    UCHAR Signature[4];   /* LBIO */
    ULONG HeaderBytes;
    ULONG HeaderChecksum;
    ULONG TableBytes;
    ULONG TableChecksum;
    ULONG TableEntries;
} CB_TABLE_HEADER, *PCB_TABLE_HEADER;

#define CB_TAG_FORWARD     0x11
#define CB_TAG_FRAMEBUFFER 0x12

typedef struct _CB_ENTRY_HEADER {
    ULONG Tag;
    ULONG Size;
} CB_ENTRY_HEADER, *PCB_ENTRY_HEADER;

typedef struct _CB_ENTRY_FORWARD {
    ULONG Tag;
    ULONG Size;
    ULONG64 PhysicalAddress;
} CB_ENTRY_FORWARD, *PCB_ENTRY_FORWARD;

typedef struct _CB_ENTRY_FRAMEBUFFER {
    ULONG Tag;
    ULONG Size;
    ULONGLONG PhysicalAddress;
    ULONG XResolution;
    ULONG YResolution;
    ULONG BytesPerLine;
    UCHAR BitsPerPixel;
    UCHAR RedMaskPos;
    UCHAR RedMaskSize;
    UCHAR GreenMaskPos;
    UCHAR GreenMaskSize;
    UCHAR BlueMaskPos;
    UCHAR BlueMaskSize;
    UCHAR ReservedMaskPos;
    UCHAR ReservedMaskSize;
} CB_ENTRY_FRAMEBUFFER, *PCB_ENTRY_FRAMEBUFFER;

/* See RFC 1071 for mathematical explanations of why we can first sum in a larger register
 * and then narrow down, why we don't need to worry about endianness, etc. */
static uint16_t HalpCbTableGetChecksum(PVOID Data, MWORD Size)
{
    MWORD WideSum = 0;
    ULONG Sum = 0;
    MWORD i = 0;
    MWORD AlignedSize = ALIGN_DOWN(Size, sizeof(MWORD));
    MWORD *LongPtr = Data;
    for (; i < AlignedSize; i += sizeof(MWORD)) {
	MWORD NewSum = WideSum + *LongPtr++;
	/* Overflow check to emulate a manual "add with carry" in C. The compiler seems
	   to be clever enough to find ways to elide the branch on most archs. */
	if (NewSum < WideSum)
	    NewSum++;
	WideSum = NewSum;
    }
    while (WideSum) {
	Sum += WideSum & 0xFFFF;
	WideSum >>= 16;
    }
    Sum = (Sum & 0xFFFF) + (Sum >> 16);

    for (; i < Size; i++) {
	ULONG v = ((PUCHAR)Data)[i];
	if (i % 2)
	    v <<= 8;
	Sum += v;

	/* Doing this unconditionally seems to be faster. */
	Sum = (Sum & 0xFFFF) + (Sum >> 16);
    }

    return (uint16_t)~Sum;
}

static PCB_TABLE_HEADER HalpCbMapTable(IN ULONG64 PhyAddr)
{
    ULONG64 AlignedAddr = PAGE_ALIGN64(PhyAddr);
    PCB_TABLE_HEADER Table = (PVOID)(MWORD)(PhyAddr - AlignedAddr + EX_DYN_VSPACE_START);
    ULONG WindowSize = PAGE_ALIGN_UP64(PhyAddr + sizeof(CB_TABLE_HEADER)) - AlignedAddr;
    if (!NT_SUCCESS(MmMapPhysicalMemory(AlignedAddr, EX_DYN_VSPACE_START,
					WindowSize, PAGE_READONLY))) {
	assert(FALSE);
	return NULL;
    }
    /* Reject the table if signature does not match or if checksum fails */
    if (memcmp(Table->Signature, "LBIO", sizeof(Table->Signature)) ||
	!Table->HeaderBytes || HalpCbTableGetChecksum(Table, sizeof(*Table))) {
	assert(FALSE);
	MmUnmapPhysicalMemory((MWORD)Table);
	return NULL;
    }
    if (PhyAddr + Table->TableBytes > PAGE_ALIGN_UP64(PhyAddr + sizeof(*Table))) {
	MmUnmapPhysicalMemory((MWORD)Table);
	WindowSize = PAGE_ALIGN_UP64(PhyAddr + Table->TableBytes) - AlignedAddr;
	if (!NT_SUCCESS(MmMapPhysicalMemory(AlignedAddr, EX_DYN_VSPACE_START,
					    WindowSize, PAGE_READONLY))) {
	    assert(FALSE);
	    return NULL;
	}
    }
    return Table;
}

NTSTATUS HalpInitCoreboot(VOID)
{
    PHYSICAL_ADDRESS PhyAddr = {};
    PUCHAR LowMemory = HalpMapTable(PhyAddr, PAGE_SIZE);
    if (!LowMemory) {
	return STATUS_SUCCESS;
    }

    /* Search the low memory and look for the coreboot header every 16 bytes */
    for (ULONG i = 0; i < PAGE_SIZE; i += 16) {
	PCB_TABLE_HEADER Table = (PVOID)&LowMemory[i];

	if (memcmp(Table->Signature, "LBIO", sizeof(Table->Signature)) ||
	    !Table->HeaderBytes || HalpCbTableGetChecksum(Table, sizeof(*Table))) {
	    continue;
	}

	if (i + Table->HeaderBytes + Table->TableBytes > PAGE_SIZE) {
	    /* Coreboot table at low memory seems to be too large. Likely a very
	     * old coreboot build. */
	    assert(FALSE);
	    goto out;
	}

	PUCHAR TableContents = &LowMemory[i + Table->HeaderBytes];
	if (HalpCbTableGetChecksum(TableContents, Table->TableBytes) !=
	    Table->TableChecksum) {
	    DbgTrace("Coreboot table signature found, but wrong checksum.\n");
	    assert(FALSE);
	    goto out;
	}

	DbgTrace("Found coreboot table header at 0x%x\n", i);

	for (MWORD Offset = 0; Offset < Table->TableBytes; ) {
	    PCB_ENTRY_HEADER Entry = (PVOID)&TableContents[Offset];
	    Offset += Entry->Size;
	    DbgTrace("  Coreboot table entry, tag 0x%02x\n", Entry->Tag);

	    if (Entry->Tag != CB_TAG_FORWARD)
		continue;

	    /* This is the forwarding entry we want. */
	    PCB_ENTRY_FORWARD Forward = (PVOID)Entry;
	    PhyAddr.QuadPart = Forward->PhysicalAddress;
	    DbgTrace("    Found forwarding entry, physical address 0x%llx.\n",
		     PhyAddr.QuadPart);
	    goto out;
	}
    }

out:
    MmUnmapPhysicalMemory((MWORD)LowMemory);
    if (!PhyAddr.QuadPart) {
	return STATUS_SUCCESS;
    }

    PCB_TABLE_HEADER Table = HalpCbMapTable(PhyAddr.QuadPart);
    if (!Table) {
	assert(FALSE);
	return STATUS_SUCCESS;
    }

    PUCHAR TableContents = &((PUCHAR)Table)[Table->HeaderBytes];
    if (HalpCbTableGetChecksum(TableContents, Table->TableBytes) !=
	Table->TableChecksum) {
	DbgTrace("Coreboot table signature found, but wrong checksum.\n");
	assert(FALSE);
	goto done;
    }

    for (MWORD Offset = 0; Offset < Table->TableBytes; ) {
	PCB_ENTRY_HEADER Entry = (PVOID)&TableContents[Offset];
	Offset += Entry->Size;
	DbgTrace("  Coreboot table entry, tag 0x%02x\n", Entry->Tag);

	if (Entry->Tag != CB_TAG_FRAMEBUFFER)
	    continue;

	/* This is the framebuffer entry we want. */
	PCB_ENTRY_FRAMEBUFFER Framebuffer = (PVOID)Entry;
	HAL_FRAMEBUFFER HalFb = {
	    .PhysicalAddress = Framebuffer->PhysicalAddress,
	    .Pitch = Framebuffer->BytesPerLine,
	    .Width = Framebuffer->XResolution,
	    .Height = Framebuffer->YResolution,
	    .BitsPerPixel = Framebuffer->BitsPerPixel,
	    .Type = MULTIBOOT_FRAMEBUFFER_TYPE_RGB
	};
	DbgTrace("    Found framebuffer entry, physical address 0x%llx, "
		 "pitch 0x%x, width %d, height %d, bits per pixel %d.\n",
		 HalFb.PhysicalAddress, HalFb.Pitch, HalFb.Width,
		 HalFb.Height, HalFb.BitsPerPixel);
	HalRegisterFramebuffer(&HalFb);
    }

done:
    MmUnmapPhysicalMemory((MWORD)Table);
    return STATUS_SUCCESS;
}
