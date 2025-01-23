/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <kernel/gen_config.h>
#include <elfloader/gen_config.h>
#ifdef CONFIG_IMAGE_BINARY
#include <image_start_addr.h>
#endif

#include <assembler.h>

.extern main

.section ".text.start"
BEGIN_FUNC(_start)
    adrp    x19, core_stack_alloc
    add     x19, x19, #0xff0
    mov     sp, x19
#ifdef CONFIG_IMAGE_BINARY
    stp     x0, x1, [sp, #-16]!
    bl      clear_bss
    /*
     * Binary images may not be loaded in the correct location.
     * Try and move ourselves so we're in the right place.
     */
    bl      fixup_image_base
    mov     x2, x0
    /* restore original arguments for next step */
    ldp     x0, x1, [sp, #-16]!
    /* fixup_image_base returns 1 if no need to move */
    cmp     x2, #1
    beq     1f
    /* otherwise, jump to the start of the new elfloader */

    br      x2
1:
#endif
    b       main
END_FUNC(_start)

#ifdef CONFIG_IMAGE_BINARY
BEGIN_FUNC(fixup_image_base)
    stp     x29, x30, [sp, #-16]!
    mov     x29, sp
    ldr     x0, =IMAGE_START_ADDR
    adr     x1, _start
    cmp     x0, x1
    beq     image_ok

    adrp    x2, _end
    add     x2, x2, #:lo12:_end
    sub     x2, x2, x1

    /* sanity check: don't want to overwrite ourselves! we assume
     * everything between _start and _archive_start is important
     * (i.e. code that might be run while relocating)
     * but allow overlap for things after _archive_start.
     */
    adrp    x3, _archive_start
    add     x3, x3, #:lo12:_archive_start

    add     x4, x0, x2 /* Dest end */

    /* check: if (end < archive_start && end >= _start) { abort } */
    cmp     x4, x3
    bge     1f

    cmp     x4, x1
    blt     1f

    b       cant_reloc

1:
    /* check: if (dest < archive_start && dest >= _start) { abort } */
    cmp     x0, x3
    bge     2f

    cmp     x0, x1
    blt     2f

cant_reloc:
    b abort

2:
    /* x0 = desired image base */
    /* x1 = current image space */
    /* x2 = image size */
    bl      memmove
    /* x0 = dest, save it to a callee-saved register while we invalidate icache */
    mov     x19, x0
    bl      flush_dcache
    bl      invalidate_icache
    mov     x0, x19
    b 1f

image_ok:
    /* already in the right place, just keep booting */
    mov x0, #1
1:
    ldp     x29, x30, [sp], #16
    ret
END_FUNC(fixup_image_base)
#endif

/* Move the elf loader out of the kernel's way */
BEGIN_FUNC(finish_relocation)
    /*
     * On aarch64 the kernel is loaded at a very high address:
     * at least above 0x0000ff8080000000. We assume that
     * the ELF loader will never get loaded in a way that overlaps
     * with the kernel, so reaching this function is an error.
     */
    b abort // should never get here!
END_FUNC(finish_relocation)

/* secondary cpu startup */
BEGIN_FUNC(secondary_startup)
    /*
     * secondary_data is a struct that looks like this:
     * 0x0 void *entry
     * 0x8 void *stack
     */
    adrp    x19, secondary_data
    add     x19, x19, #:lo12:secondary_data

    ldr     x0, [x19, #0x8]     // load stack
    mov     sp, x0
    ldr     x1, [x19, #0x0]     // load entry point

    br x1
END_FUNC(secondary_startup)
