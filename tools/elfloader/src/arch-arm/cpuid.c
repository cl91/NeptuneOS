/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <printf.h>
#include <cpuid.h>

#define CPUID_IMPL(cpuid)    (((cpuid) >> 24) &  0xff)
#define CPUID_MAJOR(cpuid)   (((cpuid) >> 20) &   0xf)
#define CPUID_VARIANT(cpuid) (((cpuid) >> 20) &   0xf)
#define CPUID_ARCH(cpuid)    (((cpuid) >> 16) &   0xf)
#define CPUID_PART(cpuid)    (((cpuid) >>  4) & 0xfff)
#define CPUID_MINOR(cpuid)   (((cpuid) >>  0) &   0xf)

#define CPUID_IMPL_ARM     'A'
#define CPUID_IMPL_DEC     'D'
#define CPUID_IMPL_QCOMM   'Q'
#define CPUID_IMPL_MARV    'V'
#define CPUID_IMPL_MOT     'M'
#define CPUID_IMPL_INTEL   'i'
#define CPUID_ARCH_ARMv4    0x1
#define CPUID_ARCH_ARMv4T   0x2
#define CPUID_ARCH_ARMv5    0x3
#define CPUID_ARCH_ARMv5T   0x4
#define CPUID_ARCH_ARMv5TE  0x5
#define CPUID_ARCH_ARMv5TEJ 0x6
#define CPUID_ARCH_ARMv6    0x7
#define CPUID_ARCH_CPUID    0xF

#if __has_attribute(optimize)
#define OPTIMIZE_CHANGE __attribute__((optimize(1)))
#else
#define OPTIMIZE_CHANGE __attribute__((optnone))
#endif

/*
 * At O2 the switch gets optimised into a table, (at least on GCC 7.4 and 8.2)
 * which isn't handled properly for position independent code (i.e. when booting on EFI).
 */
OPTIMIZE_CHANGE static const char *cpuid_get_implementer_str(uint32_t cpuid)
{
    switch (CPUID_IMPL(cpuid)) {
    case CPUID_IMPL_ARM:
        return "ARM Ltd.";
    case CPUID_IMPL_DEC:
        return "Digital Equipment Corp.";
    case CPUID_IMPL_QCOMM:
        return "Qualcomm Inc.";
    case CPUID_IMPL_MARV:
        return "Marvell Semiconductor Inc.";
    case CPUID_IMPL_MOT:
        return "Motorola, Freescale Semiconductor Inc.";
    case CPUID_IMPL_INTEL:
        return "Intel Corp.";
    default:
        return "<Reserved>";
    }
}

OPTIMIZE_CHANGE static const char *cpuid_get_arch_str(uint32_t cpuid)
{
    switch (CPUID_ARCH(cpuid)) {
    case CPUID_ARCH_ARMv4:
        return "ARMv4";
    case CPUID_ARCH_ARMv4T:
        return "ARMv4T";
    case CPUID_ARCH_ARMv5:
        return "ARMv5 (obsolete)";
    case CPUID_ARCH_ARMv5T:
        return "ARMv5T";
    case CPUID_ARCH_ARMv5TE:
        return "ARMv5TE";
    case CPUID_ARCH_ARMv5TEJ:
        return "ARMv5TEJ";
    case CPUID_ARCH_ARMv6:
        return "ARMv6";
    case CPUID_ARCH_CPUID:
        return "Defined by CPUID scheme";
    default:
        return "<Reserved>";
    }
}


OPTIMIZE_CHANGE static const char *cpuid_get_arm_part_str(uint32_t cpuid)
{
    switch (CPUID_PART(cpuid)) {
    case 0xC05:
        return "Cortex-A5";
    case 0xC07:
        return "Cortex-A7";
    case 0xC08:
        return "Cortex-A8";
    case 0xC09:
        return "Cortex-A9";
    case 0xC0D:
        return "Cortex-A12";
    case 0xC0F:
        return "Cortex-A15";
    case 0xC0E:
        return "Cortex-A17";
    case 0xD01:
        return "Cortex-A32";
    case 0xD02:
        return "Cortex-A34";
    case 0xD03:
        return "Cortex-A53";
    case 0xD04:
        return "Cortex-A35";
    case 0xD05:
        return "Cortex-A55";
    case 0xD06:
        return "Cortex-A65";
    case 0xD07:
        return "Cortex-A57";
    case 0xD08:
        return "Cortex-A72";
    case 0xD09:
        return "Cortex-A73";
    case 0xD0A:
        return "Cortex-A75";
    case 0xD0B:
        return "Cortex-A76";
    case 0xD0C:
        return "Neoverse N1";
    case 0xD0D:
        return "Cortex-A77";
    case 0xD0E:
        return "Cortex-A76AE";
    case 0xD40:
        return "Neoverse V1";
    case 0xD41:
        return "Cortex-A78";
    case 0xD42:
        return "Cortex-A78AE";
    case 0xD43:
        return "Cortex-A65AE";
    case 0xD44:
        return "Cortex-X1";
    case 0xD46:
        return "Cortex-A510";
    case 0xD47:
        return "Cortex-A710";
    case 0xD48:
        return "Cortex-X2";
    case 0xD49:
        return "Neoverse N2";
    case 0xD4A:
        return "Neoverse E1";
    case 0xD4B:
        return "Cortex-78C";
    default:
        return NULL;
    }
}

void print_cpuid(void)
{
    uint32_t cpuid;
    const char *part = NULL;
    cpuid = read_cpuid_id();

    if (CPUID_IMPL(cpuid) == CPUID_IMPL_ARM) {
        part = cpuid_get_arm_part_str(cpuid);
    }

    printf("CPU: %s ", cpuid_get_implementer_str(cpuid));
    if (CPUID_ARCH(cpuid) != CPUID_ARCH_CPUID) {
        printf("%s ", cpuid_get_arch_str(cpuid));
    }
    if (part == NULL) {
        printf("Part: 0x%03x ", CPUID_PART(cpuid));
    } else {
        printf("%s ", part);
    }

    printf("r%dp%d", CPUID_MAJOR(cpuid), CPUID_MINOR(cpuid));
    printf("\n");
}

int get_cortex_a_part(void)
{
    uint32_t cpuid;
    cpuid = read_cpuid_id();
    if (CPUID_ARCH(cpuid) == CPUID_ARCH_CPUID && CPUID_IMPL(cpuid) == CPUID_IMPL_ARM) {
        return CPUID_PART(cpuid) & 0xFF;
    } else {
        return -1;
    }
}
