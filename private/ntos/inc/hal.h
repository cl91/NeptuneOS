#pragma once

#include <nt.h>
#include <services.h>
#include <printf.h>
#include <ke.h>

#include <pshpack1.h>
/* Multiboot2 Framebuffer */
typedef struct multiboot2_fb {
    ULONG64 PhysicalAddress;
    ULONG Pitch;
    ULONG Width;
    ULONG Height;
    UCHAR BitsPerPixel;
    UCHAR Type;
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
NTSTATUS HalEnableSystemTimer(OUT PIRQ_HANDLER IrqHandler,
			      IN ULONG64 Period);
NTSTATUS HalMaskUnusableInterrupts(VOID);

/* cmos.c */
BOOLEAN HalQueryRealTimeClock(OUT PTIME_FIELDS Time);
BOOLEAN HalSetRealTimeClock(IN PTIME_FIELDS Time);

/* smbios.c */
VOID HalRegisterEfiSystemTablePointer(IN ULONG64 PhysAddr);

/* vga.c */
VOID HalRegisterFramebuffer(IN PHAL_FRAMEBUFFER Fb);
VOID HalDisplayString(PCSTR String);

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
