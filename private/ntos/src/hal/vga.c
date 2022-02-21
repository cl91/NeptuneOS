#include "halp.h"
#include <ctype_inline.h>

static ULONG HalpVgaCursorPositionHorizontal;
static ULONG HalpVgaCursorPositionVertical;
static BOOLEAN HalpVgaInitialized;

static VOID HalpVgaDisableCursor()
{
    WRITE_PORT_UCHAR(VGA_CURSOR_CONTROL_PORT, 0x0A);
    WRITE_PORT_UCHAR(VGA_CURSOR_DATA_PORT, 0x20);
}

static VOID HalpVgaScrollLine()
{
    memmove((PVOID) VGA_VIDEO_PAGE_VADDR,
	    (PVOID) (VGA_VIDEO_PAGE_VADDR + 2 * VGA_MODE_HORIZONTAL),
	    2 * VGA_MODE_HORIZONTAL * (VGA_MODE_VERTICAL-1));
    PUCHAR DestAddr = (PUCHAR) (VGA_VIDEO_PAGE_VADDR + 2 * VGA_MODE_HORIZONTAL
				* (VGA_MODE_VERTICAL-1));
    for (ULONG i = 0; i < VGA_MODE_HORIZONTAL; i++) {
	*DestAddr++ = 0;
	*DestAddr++ = VGA_BG_COLOR;
    }
}

VOID HalDisplayStringEx(UCHAR Color, PCSTR String)
{
    /* If we are not even initialized, simply return. */
    if (!HalpVgaInitialized) {
	return;
    }
    while (*String != 0) {
	volatile PCHAR Video = (volatile PCHAR)
	    (VGA_VIDEO_PAGE_VADDR + 2 * (VGA_MODE_HORIZONTAL
					 * HalpVgaCursorPositionVertical
					 + HalpVgaCursorPositionHorizontal));
	UCHAR Chr = *String;
	if (isprint(Chr)) {
	    *Video++ = Chr;
	    *Video = Color;
	    HalpVgaCursorPositionHorizontal++;
	} else if (Chr == '\t') {
	    HalpVgaCursorPositionHorizontal += 8;
	    HalpVgaCursorPositionHorizontal >>= 3;
	    HalpVgaCursorPositionHorizontal <<= 3;
	} else if (Chr == '\n') {
	    if (HalpVgaCursorPositionHorizontal < VGA_MODE_HORIZONTAL) {
		HalpVgaCursorPositionVertical++;
	    }
	    HalpVgaCursorPositionHorizontal = 0;
	} else if (Chr == '\b') {
	    Video--;
	    *Video-- = Color;
	    *Video = ' ';
	    if (HalpVgaCursorPositionHorizontal == 0) {
		HalpVgaCursorPositionVertical--;
		HalpVgaCursorPositionHorizontal = VGA_MODE_HORIZONTAL - 1;
	    } else {
		HalpVgaCursorPositionHorizontal--;
	    }
	}
	String++;
	if (HalpVgaCursorPositionHorizontal >= VGA_MODE_HORIZONTAL) {
	    HalpVgaCursorPositionVertical++;
	    HalpVgaCursorPositionHorizontal = 0;
	}
	assert(HalpVgaCursorPositionVertical <= VGA_MODE_VERTICAL);
	if (HalpVgaCursorPositionVertical >= VGA_MODE_VERTICAL) {
	    HalpVgaScrollLine();
	    HalpVgaCursorPositionVertical--;
	}
    }
    assert(HalpVgaCursorPositionHorizontal < VGA_MODE_HORIZONTAL);
    assert(HalpVgaCursorPositionVertical < VGA_MODE_VERTICAL);
}

static inline VOID HalpVgaClearScreen()
{
    volatile PCHAR Video = (volatile PCHAR) (VGA_VIDEO_PAGE_VADDR);
    for (ULONG i = 0; i < PAGE_SIZE/2; i++) {
	*Video++ = 0;
	*Video++ = VGA_BG_COLOR;
    }
}

static inline NTSTATUS HalpInitVgaIoPort()
{
    RET_ERR(HalpEnableIoPort(VGA_CURSOR_CONTROL_PORT));
    RET_ERR(HalpEnableIoPort(VGA_CURSOR_DATA_PORT));
    return STATUS_SUCCESS;
}

NTSTATUS HalpInitVga()
{
    RET_ERR(MmMapPhysicalMemory(VGA_VIDEO_PAGE_PADDR,
				VGA_VIDEO_PAGE_VADDR, PAGE_SIZE));
    RET_ERR(HalpInitVgaIoPort());
    HalpVgaDisableCursor();
    HalpVgaClearScreen();
    HalpVgaInitialized = TRUE;
    return STATUS_SUCCESS;
}
