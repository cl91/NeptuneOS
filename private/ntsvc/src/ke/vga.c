#include <nt.h>
#include <ntos.h>
#include <ntsvc.h>

#define VGA_VADDR_BASE		(0x10000000)
#define VGA_VADDR_BASE_PN	(VGA_VADDR_BASE >> MM_PAGE_BITS)
#define VGA_VIDEO_PAGE		(0xB8000)
#define VGA_VIDEO_PN		(VGA_VIDEO_PAGE >> MM_PAGE_BITS)

VOID KiVgaWriteString(UCHAR Color, PCSTR String)
{
    volatile PCHAR Video = (volatile PCHAR) (VGA_VADDR_BASE + VGA_VIDEO_PAGE);
    while (*String != 0) {
	*Video++ = *String++;
	*Video++ = Color;
    }
}

VOID KiInitVga()
{
    BUGCHECK_IF_ERR(MmReserveVirtualMemory(&ExNtsvcProcess.VaddrSpace, VGA_VADDR_BASE_PN + VGA_VIDEO_PN, 1));
    BUGCHECK_IF_ERR(MmCommitIoPage(&ExNtsvcProcess.VaddrSpace, VGA_VIDEO_PN, VGA_VADDR_BASE_PN + VGA_VIDEO_PN));
    KiVgaWriteString(3, "Hello, world!");
}
