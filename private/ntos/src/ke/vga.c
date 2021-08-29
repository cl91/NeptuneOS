#include <string.h>
#include "ki.h"

static X86_IOPORT KiVgaCursorControlPort;
static X86_IOPORT KiVgaCursorDataPort;

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

static NTSTATUS KiInitVgaIoPort()
{
    extern CNODE MiNtosCNode;
    RET_ERR(KeEnableIoPortX86(&MiNtosCNode, VGA_CURSOR_CONTROL_PORT, &KiVgaCursorControlPort));
    RET_ERR(KeEnableIoPortX86(&MiNtosCNode, VGA_CURSOR_DATA_PORT, &KiVgaCursorDataPort));
    return STATUS_SUCCESS;
}

VOID KiInitVga()
{
    HALT_IF_ERR(MmMapPhysicalMemory(VGA_VIDEO_PAGE_PADDR,
				    VGA_VIDEO_PAGE_VADDR, PAGE_SIZE));
    HALT_IF_ERR(KiInitVgaIoPort());
    KiVgaDisableCursor();
    KiVgaClearScreen();
    KiVgaWriteString("Welcome!");
}
