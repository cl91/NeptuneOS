#include <string.h>
#include <ctype_inline.h>
#include "ki.h"

/* TODO: Move this to ntos/hal */

static X86_IOPORT KiVgaCursorControlPort;
static X86_IOPORT KiVgaCursorDataPort;
static ULONG KiVgaCursorPositionHorizontal;
static ULONG KiVgaCursorPositionVertical;

#define VGA_MODE_HORIZONTAL		(80)
#define VGA_MODE_VERTICAL		(25)
#define VGA_CURSOR_CONTROL_PORT		(0x3D4)
#define VGA_CURSOR_DATA_PORT		(0x3D5)

static NTSTATUS KiVgaDisableCursor()
{
    RET_ERR(KeWritePort8(&KiVgaCursorControlPort, 0x0A));
    RET_ERR(KeWritePort8(&KiVgaCursorDataPort, 0x20));
    return STATUS_SUCCESS;
}

static VOID KiVgaScrollLine()
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

VOID KeVgaWriteStringEx(UCHAR Color, PCSTR String)
{
    while (*String != 0) {
	volatile PCHAR Video = (volatile PCHAR)
	    (VGA_VIDEO_PAGE_VADDR + 2 * (VGA_MODE_HORIZONTAL
					 * KiVgaCursorPositionVertical
					 + KiVgaCursorPositionHorizontal));
	UCHAR Chr = *String;
	if (isprint(Chr)) {
	    *Video++ = Chr;
	    *Video = Color;
	    KiVgaCursorPositionHorizontal++;
	} else if (Chr == '\t') {
	    KiVgaCursorPositionHorizontal += 8;
	    KiVgaCursorPositionHorizontal >>= 3;
	    KiVgaCursorPositionHorizontal <<= 3;
	} else if (Chr == '\n') {
	    KiVgaCursorPositionHorizontal = 0;
	    KiVgaCursorPositionVertical++;
	}
	String++;
	if (KiVgaCursorPositionHorizontal >= VGA_MODE_HORIZONTAL) {
	    KiVgaCursorPositionVertical++;
	    KiVgaCursorPositionHorizontal = 0;
	}
	assert(KiVgaCursorPositionVertical <= VGA_MODE_VERTICAL);
	if (KiVgaCursorPositionVertical >= VGA_MODE_VERTICAL) {
	    KiVgaScrollLine();
	    KiVgaCursorPositionVertical--;
	}
    }
    assert(KiVgaCursorPositionHorizontal < VGA_MODE_HORIZONTAL);
    assert(KiVgaCursorPositionVertical < VGA_MODE_VERTICAL);
}

static VOID KiVgaClearScreen()
{
    volatile PCHAR Video = (volatile PCHAR) (VGA_VIDEO_PAGE_VADDR);
    for (ULONG i = 0; i < PAGE_SIZE/2; i++) {
	*Video++ = 0;
	*Video++ = VGA_BG_COLOR;
    }
}

static NTSTATUS KiInitVgaIoPort()
{
    RET_ERR(KeEnableIoPort(VGA_CURSOR_CONTROL_PORT, &KiVgaCursorControlPort));
    RET_ERR(KeEnableIoPort(VGA_CURSOR_DATA_PORT, &KiVgaCursorDataPort));
    return STATUS_SUCCESS;
}

#define OS_BANNER	"Neptune OS v0.0.1 (" GIT_HEAD_SHA_SHORT ")"

VOID KiInitVga()
{
    HALT_IF_ERR(MmMapPhysicalMemory(VGA_VIDEO_PAGE_PADDR,
				    VGA_VIDEO_PAGE_VADDR, PAGE_SIZE));
    HALT_IF_ERR(KiInitVgaIoPort());
    KiVgaDisableCursor();
    KiVgaClearScreen();
    KeVgaWriteString(OS_BANNER "    ");
}
