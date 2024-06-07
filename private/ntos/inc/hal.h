#pragma once

#include <nt.h>
#include <printf.h>

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

/* TODO: This is for x86 and PIC only. We don't support IOAPIC yet. */
#define TIMER_IRQ_LINE		0

/* TODO: Most BIOS set the frequency divider to either 65535 or 0 (representing
 * 65536). We assume it is 65536. We should really be setting the frequency
 * divider ourselves. */
#define TIMER_TICK_PER_SECOND	(1193182 >> 16)

#define TIMER_RESOLUTION_IN_100NS	(10000000 / TIMER_TICK_PER_SECOND)

/* init.c */
NTSTATUS HalInitSystemPhase0(VOID);
NTSTATUS HalInitSystemPhase1(VOID);

/* acpi.c */
VOID HalAcpiRegisterRsdp(IN PHAL_ACPI_RSDP Rsdp);
CM_PARTIAL_RESOURCE_DESCRIPTOR HalAcpiGetRsdtResource();

/* cmos.c */
BOOLEAN HalQueryRealTimeClock(OUT PTIME_FIELDS Time);
BOOLEAN HalSetRealTimeClock(IN PTIME_FIELDS Time);

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
