#pragma once

#include <nt.h>
#include <services.h>
#include <printf.h>
#include <ke.h>
#include <io.h>
#include <wmidata.h>

#include <pshpack1.h>
/* Multiboot2 Framebuffer */
typedef struct multiboot2_fb {
    ULONG64 PhysicalAddress;
    ULONG Pitch;
    ULONG Width;
    ULONG Height;
    UCHAR BitsPerPixel;
    UCHAR Type;
} HAL_FRAMEBUFFER_INFO, *PHAL_FRAMEBUFFER_INFO;

typedef struct _HAL_VGA_FONT {
    ULONG Width;
    ULONG Height;
    PCSTR FontData;
} HAL_VGA_FONT, *PHAL_VGA_FONT;

/*
 * Some x86 clamshell design devices use portrait tablet screens and a display
 * engine which cannot rotate in hardware, so we need to rotate the fbcon to
 * compensate. Unfortunately these (cheap) devices also typically have quite
 * generic DMI data, so we match on a combination of DMI data, screen resolution
 * and a list of known BIOS dates to avoid false positives.
 */
typedef enum _HAL_PANEL_ORIENTATION {
    PANEL_ORIENTATION_DEFAULT,
    PANEL_ORIENTATION_RIGHT_UP,	/* Screen should be rotated 90 degrees counterclockwise */
    PANEL_ORIENTATION_LEFT_UP,	/* Screen should be rotated 90 degrees clockwise */
} HAL_PANEL_ORIENTATION;

typedef struct _HAL_FRAMEBUFFER {
    LIST_ENTRY Link;
    LIST_ENTRY DriverLink;
    PIO_DRIVER_OBJECT DriverObject;
    MWORD VirtualBase;
    PHAL_VGA_FONT VgaFont;
    ULONG CursorPositionColumn;
    ULONG CursorPositionRow;
    ULONG CursorMaxColumns;
    ULONG CursorMaxRows;
    ULONG ConsoleBufferSize;
    HAL_FRAMEBUFFER_INFO Info;
    HAL_PANEL_ORIENTATION PanelOrientation;
    UCHAR BlueIndex;
    UCHAR GreenIndex;
    UCHAR RedIndex;
    BOOLEAN TextMode;
    UCHAR ConsoleBuffer[];
} HAL_FRAMEBUFFER, *PHAL_FRAMEBUFFER;

/* Root System Descriptor Pointer */
typedef struct _HAL_ACPI_RSDP {
    CHAR Signature[8];
    UCHAR Checksum;
    CHAR OemId[6];
    UCHAR Revision;
    ULONG RsdtAddress;
    ULONG Length;
    ULONG64 XsdtAddress;
    UCHAR ExtendedChecksum;
    CHAR Reserved[3];
} HAL_ACPI_RSDP, *PHAL_ACPI_RSDP;
#include <poppack.h>

/* init.c */
NTSTATUS HalInitSystemPhase0(VOID);
NTSTATUS HalInitSystemPhase1(VOID);

/* acpi.c */
VOID HalAcpiRegisterRsdp(IN PHAL_ACPI_RSDP Rsdp);
ULONG64 HalAcpiGetRsdt(OUT ULONG *Length);
VOID HalAcpiDumpRsdp(IN PHAL_ACPI_RSDP Rsdp, IN ULONG Indentation);
NTSTATUS HalAllocateIrq(IN ULONG Irq);
NTSTATUS HalDeallocateIrq(IN ULONG Irq);
NTSTATUS HalGetIrqCap(IN PIRQ_HANDLER IrqHandler,
		      MWORD Root, MWORD Index, UINT8 Depth);
NTSTATUS HalEnableSystemTimer(OUT PIRQ_HANDLER IrqHandler);
VOID HalSetSystemTimer(IN ULONG64 RelativeDueTimeIn100ns);
NTSTATUS HalMaskUnusableInterrupts(VOID);
ULONG_PTR HalComputeInterruptMessageAddress(IN ULONG ProcessorId);
ULONG HalComputeInterruptMessageData(IN ULONG Vector);

/* cmos.c */
BOOLEAN HalQueryRealTimeClock(OUT PTIME_FIELDS Time);
BOOLEAN HalSetRealTimeClock(IN PTIME_FIELDS Time);

/* smbios.c */
VOID HalRegisterEfiSystemTablePointer(IN ULONG64 PhysAddr,
				      IN ULONG Size);
PMSSmBios_RawSMBiosTables HalGetRawSmbiosTables();

/* vga.c */
VOID HalRegisterBootFrameBuffer(IN PHAL_FRAMEBUFFER_INFO Info,
				IN UCHAR BlueIndex,
				IN UCHAR GreenIndex,
				IN UCHAR RedIndex);
VOID HalDisplayString(PCSTR String);
ULONG HalGetConsoleMaxColumns();
ULONG HalGetConsoleMaxRows();

static inline __attribute__((format(printf, 1, 2))) ULONG HalVgaPrint(PCSTR Format, ...)
{
    char buf[512];
    va_list arglist;
    va_start(arglist, Format);
    vsnprintf(buf, sizeof(buf), Format, arglist);
    va_end(arglist);
    HalDisplayString(buf);
    return 0;
}
