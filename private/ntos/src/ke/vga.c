#include <string.h>
#include <ctype_inline.h>
#include "ki.h"

static X86_IOPORT KiVgaCursorControlPort;
static X86_IOPORT KiVgaCursorDataPort;
static ULONG KiVgaCursorPositionHorizontal;
static ULONG KiVgaCursorPositionVertical;

#define VGA_MODE_HORIZONTAL		(80)
#define VGA_MODE_VERTICAL		(25)
#define VGA_BLUE			(1)
#define VGA_WHITE			(15)
#define VGA_BG_COLOR			(VGA_BLUE << 4)
#define VGA_FG_COLOR			(VGA_WHITE)
#define VGA_TEXT_COLOR			(VGA_BG_COLOR | VGA_FG_COLOR)
#define VGA_CURSOR_CONTROL_PORT		(0x3D4)
#define VGA_CURSOR_DATA_PORT		(0x3D5)

static NTSTATUS KiReadPort8(IN PX86_IOPORT Port,
			    OUT UCHAR *Out)
{
    assert(Out != NULL);
    seL4_X86_IOPort_In8_t Reply = seL4_X86_IOPort_In8(Port->TreeNode.Cap,
						      Port->PortNum);
    if (Reply.error != 0) {
	DbgTrace("Reading IO port 0x%x (cap 0x%zx) failed with error %d\n",
		 Port->PortNum, Port->TreeNode.Cap, Reply.error);
	KeDbgDumpIPCError(Reply.error);
	return SEL4_ERROR(Reply.error);
    }
    *Out = Reply.result;
    return STATUS_SUCCESS;
}

static NTSTATUS KiWritePort8(IN PX86_IOPORT Port,
			     IN UCHAR Data)
{
    int Error = seL4_X86_IOPort_Out8(Port->TreeNode.Cap, Port->PortNum, Data);
    if (Error != 0) {
	DbgTrace("Writing IO port 0x%x (cap 0x%zx) with data 0x%x failed with error %d\n",
		 Port->PortNum, Port->TreeNode.Cap, Data, Error);
	KeDbgDumpIPCError(Error);
	return SEL4_ERROR(Error);
    }
    return STATUS_SUCCESS;
}

static NTSTATUS KiVgaDisableCursor()
{
    RET_ERR(KiWritePort8(&KiVgaCursorControlPort, 0x0A));
    RET_ERR(KiWritePort8(&KiVgaCursorDataPort, 0x20));
    return STATUS_SUCCESS;
}

static VOID KiVgaScrollLine()
{
    memmove((PVOID) (VGA_VIDEO_PAGE_VADDR + 2 * VGA_MODE_HORIZONTAL),
	    (PVOID) VGA_VIDEO_PAGE_VADDR,
	    2 * VGA_MODE_HORIZONTAL * (VGA_MODE_VERTICAL-1));
    PUCHAR DestAddr = (PUCHAR) (VGA_VIDEO_PAGE_VADDR + 2 * VGA_MODE_HORIZONTAL
				* (VGA_MODE_VERTICAL-1));
    for (ULONG i = 0; i < VGA_MODE_HORIZONTAL; i++) {
	*DestAddr++ = 0;
	*DestAddr++ = VGA_BG_COLOR;
    }
}

static VOID KiVgaWriteStringEx(UCHAR Color, PCSTR String)
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

static inline VOID KiVgaWriteString(PCSTR String)
{
    KiVgaWriteStringEx(VGA_TEXT_COLOR, String);
}

/*
 * TODO: Check if calling process has the required privilege
 */
NTSTATUS NtDisplayString(IN PTHREAD Thread,
			 IN PCSTR String)
{
    KiVgaWriteString(String);
    return STATUS_SUCCESS;
}

static NTSTATUS KiInitVgaIoPort()
{
    extern CNODE MiNtosCNode;
    RET_ERR(KeEnableIoPortX86(&MiNtosCNode, VGA_CURSOR_CONTROL_PORT, &KiVgaCursorControlPort));
    RET_ERR(KeEnableIoPortX86(&MiNtosCNode, VGA_CURSOR_DATA_PORT, &KiVgaCursorDataPort));
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
    KiVgaWriteString(OS_BANNER "\n");
}
