/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 * Copyright 2021, HENSOLDT Cyber
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#pragma once

#include <types.h>

typedef uintptr_t paddr_t;
typedef uintptr_t vaddr_t;

#define PAGE_BITS           12

#define BIT(x)              (1 << (x))
#define MASK(n)             (BIT(n) - 1)
#define MIN(a, b)           (((a) < (b)) ? (a) : (b))
#define IS_ALIGNED(n, b)    (!((n) & MASK(b)))
#define ROUND_UP(n, b)      (((((n) - 1) >> (b)) + 1) << (b))
#define ROUND_DOWN(n, b) (((n) >> (b)) << (b))
#define ALIGN(n)            __attribute__((__aligned__(n)))
#if __has_attribute(externally_visible)
#define VISIBLE             __attribute__((externally_visible))
#else
#define VISIBLE
#endif
#define WEAK                __attribute__((weak))
#define NORETURN            __attribute__((noreturn))
#define UNREACHABLE()       __builtin_unreachable()
#define UNUSED              __attribute__((unused))
#define UNUSED_VARIABLE(x)  ((void)(x))
#define ARRAY_SIZE(a)       (sizeof(a)/sizeof((a)[0]))
#define NULL                ((void *)0)

/*
 * Information about an image we are loading.
 */
struct image_info {
    /* Start/end byte of the image in physical memory. */
    paddr_t phys_region_start;
    paddr_t phys_region_end;

    /* Start/end byte in virtual memory the image requires to be located. */
    vaddr_t virt_region_start;
    vaddr_t virt_region_end;

    /* Virtual address of the user image's entry point. */
    vaddr_t  virt_entry;

    /* The seL4 kernel boot interface does not have the parameter virt_entry,
     * but expect a parameter with the offset between the physical and virtual
     * addresses of the image, where this must hold:
     *     virt_address + phys_virt_offset = phys_address
     * Practically, the offset is usually a positive value, because the virtual
     * address is a low value and the actually physical address is much greater.
     * But in general, there is no restrictions on the physical and virtual
     * image location. Defining phys_virt_offset as a signed value might seem
     * the intuitive choice how to handle this, but there is are two catches
     * here that break the C rules. We can't cover the full integer range then
     * and overflows/underflows are well defined for unsigned values only. They
     * are undefined for signed values, even if such operations practically work
     * in many cases due to how the compiler/machine implements negative
     * integers using the two's-complement.
     * Assume 32-bit system with virt_address=0xc0000000 and phys_address=0,
     * then phys_virt_offset would have to be -0xc0000000. This value is not
     * in the 32-bit signed integer range. With unsigned integers, calculating
     * 0 - 0xc0000000 results in 0x40000000 after an underflow, the reverse
     * calculation 0xc0000000 + 0x40000000 results in 0 again after overflow. If
     * 0x40000000 is a signed integer, result is likely the same, but the whole
     * operation is completely undefined by C rules.
     */
    word_t phys_virt_offset;
};

extern struct image_info kernel_info;
extern struct image_info user_info;
extern void const *dtb;

/* Symbols defined in linker scripts. */
extern char _text[];
extern char _end[];
extern char _archive_start[];
extern char _archive_start_end[];

/* Clear BSS. */
void clear_bss(void);

/* Load images. */
int load_images(
    struct image_info *kernel_info,
    struct image_info *user_info,
    unsigned int max_user_images,
    unsigned int *num_images,
    void const *bootloader_dtb,
    void const **chosen_dtb,
    size_t *chosen_dtb_size);

/* Platform functions */
void platform_init(void);
void init_cpus(void);
int plat_console_putchar(unsigned int c);
