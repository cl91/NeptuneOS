#include <nt.h>
#include <ntos.h>
#include <string.h>

#define VGA_BLUE			(1)
#define VGA_WHITE			(15)
#define VGA_BG_COLOR			(VGA_BLUE << 4)
#define VGA_FG_COLOR			(VGA_WHITE)
#define VGA_TEXT_COLOR			(VGA_BG_COLOR | VGA_FG_COLOR)

static VOID KiVgaWriteStringEx(UCHAR Color, PCSTR String)
{
    volatile PCHAR Video = (volatile PCHAR) (VGA_VIDEO_PAGE_VADDR);
    while (*String != 0) {
	*Video++ = *String++;
	*Video++ = Color;
    }
}

static VOID KiVgaClearScreen()
{
    volatile PCHAR Video = (volatile PCHAR) (VGA_VIDEO_PAGE_VADDR);
    for (ULONG i = 0; i < PAGE_SIZE/2; i++) {
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
    BUGCHECK_IF_ERR(MmMapPhysicalMemory(VGA_VIDEO_PAGE_PADDR,
					VGA_VIDEO_PAGE_VADDR, PAGE_SIZE));
    KiVgaClearScreen();
    KiVgaWriteString("Welcome!");
}
