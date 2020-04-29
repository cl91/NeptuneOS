#include <nt.h>
#include <ntos.h>
#include <string.h>

#define VGA_VADDR_BASE		(0x0)
#define VGA_VADDR_BASE_PN	(VGA_VADDR_BASE >> MM_PAGE_BITS)
#define VGA_VIDEO_PAGE		(0xB8000)
#define VGA_VIDEO_PN		(VGA_VIDEO_PAGE >> MM_PAGE_BITS)
#define VGA_BLUE		(1)
#define VGA_WHITE		(15)
#define VGA_BG_COLOR		(VGA_BLUE << 4)
#define VGA_FG_COLOR		(VGA_WHITE)
#define VGA_TEXT_COLOR		(VGA_BG_COLOR | VGA_FG_COLOR)

static VOID KiVgaWriteStringEx(UCHAR Color, PCSTR String)
{
    volatile PCHAR Video = (volatile PCHAR) (VGA_VADDR_BASE + VGA_VIDEO_PAGE);
    while (*String != 0) {
	*Video++ = *String++;
	*Video++ = Color;
    }
}

static VOID KiVgaClearScreen()
{
    volatile PCHAR Video = (volatile PCHAR) (VGA_VADDR_BASE + VGA_VIDEO_PAGE);
    for (ULONG i = 0; i < MM_PAGE_SIZE/2; i++) {
	*Video++ = 0;
	*Video++ = VGA_BG_COLOR;
    }
}

static VOID KiVgaWriteString(PCSTR String)
{
    return KiVgaWriteStringEx(VGA_TEXT_COLOR, String);
}

VOID KiInitVga()
{
    BUGCHECK_IF_ERR(MmReserveVirtualMemory(VGA_VADDR_BASE_PN + VGA_VIDEO_PN, 1));
    BUGCHECK_IF_ERR(MmCommitIoPage(VGA_VIDEO_PN, VGA_VADDR_BASE_PN + VGA_VIDEO_PN));
    KiVgaClearScreen();
    KiVgaWriteString("Welcome!");
}
