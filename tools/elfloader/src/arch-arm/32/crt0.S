/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <kernel/gen_config.h>
#include <elfloader/gen_config.h>
#include <assembler.h>
#include <armv/assembler.h>

.extern main
.extern non_boot_main

.section ".text.start"

BEGIN_FUNC(_start)
#ifdef CONFIG_ELFLOADER_ARMV8_LEAVE_AARCH64
    /* Include an Aarch64 preamble that switches to aarch32 */
    .incbin "crt0_64.bin"
BEGIN_FUNC(_start32)
#endif // CONFIG_ELFLOADER_ARMV8_LEAVE_AARCH64

    /* If we're not booting under EFI, r2 will contain a pointer to the DTB */
    mov r0, r2

    /* Disable Async aborts that might be pending from bootloader */
    cpsid   ifa

    /* r0 contains the FDT address from the bootloader */
#if CONFIG_MAX_NUM_NODES > 1
    /* Enable SMP */
    mrc     ACTLR(r1)
    orr     r1, r1, #(1 << 6)       /* enable SMP bit   */
#ifdef CONFIG_ARM_CORTEX_A9
    orr     r1, r1, #1              /* enable FW bit    */
#endif
    mcr     ACTLR(r1)
#endif /* CONFIG_MAX_NUM_NODES > 1 */

    ldr sp, =core_stack_alloc + 0xff0

#ifndef CONFIG_IMAGE_EFI
    /*
     * clear the BSS section, since it may not be clear yet.
     * Under EFI, this is done earlier in the boot process.
     */
    push    {r0}
    bl      clear_bss
    pop     {r0}
#endif

    b       main
END_FUNC(_start)

/* Move the elf loader out of the kernel's way */
BEGIN_FUNC(finish_relocation)
#if CONFIG_IMAGE_EFI
    // r0 = offset between current base address and new base address
    // r1 = _DYNAMIC pointer (current base address)
    // r2 = total offset (new_base)
    mov r8, r1 // move to r8

    // figure out relocated address of continue_boot
    adr r1, LC2
    ldmia r1, {r3, r4, r5}

    // r3 = stack pointer (in current program)
    // r4 = continue_boot (in current program)
    // r5 = current base address (_text, the start of the binary)

    sub sp, r3, r0                  // point sp to new stack
    sub r4, r4, r0                  // continue_boot address in relocated elfloader

    // self_reloc expects:
    // r0 = current base address
    // r1 = dynamic section pointer
    // r2 = new base address
    // r3 = 0

    mov r0, r5                      // current base address
    mov r1, r8                      // put _DYNAMIC back
    // r2 is new base address, passed from relocate_below_kernel()
    mov r3, #0                      // NULL r3

    push {r4}                       // save continue_boot address

    bl _relocate

    pop {r4}
    mov r0, #1
    blx r4
    b abort // should never get here!
#else
    /* On non-EFI, the image cannot be relocated.
     * If you hit this, you probably need to modify the ELF loader
     * load address.
     */
    mov pc, lr
#endif
END_FUNC(finish_relocation)
.align 2
.type LC2, #object
LC2:
.word core_stack_alloc + 0xff0  // r3
.word continue_boot             // r4
.word _text                     // r5
.size LC2, . - LC2

#if CONFIG_MAX_NUM_NODES > 1
BEGIN_FUNC(secondary_startup)
    /* Invalidate caches before proceeding... */
    mov     r0, #0
    mcr     IIALL(r0)
    dcache  isw

    /* Disable Async aborts that might be pending from bootloader */
    cpsid   ifa

    /* Enable SMP */
    mrc     ACTLR(r0)
    orr     r0, r0, #(1 << 6)       /* enable SMP bit   */
#ifdef CONFIG_ARM_CORTEX_A9
    orr     r0, r0, #1              /* enable FW bit    */
#endif
    mcr     ACTLR(r0)

    /*
     * secondary_data is a struct like this:
     * 0x0 void *entry
     * 0x4 void *stack
     */
    ldr     r0, =secondary_data
    ldr     r1, [r0, #0x4]         /* load stack */
    mov     sp, r1

    ldr     r2, [r0]               /* load entry point */

    /* core_entry expects sp as its first argument */
    mov     r0, r1
    bx r2
END_FUNC(secondary_startup)
#endif /* CONFIG_MAX_NUM_NODES */

/*
 * Symbols required for libgcc.
 */
.global raise
.global __aeabi_unwind_cpp_pr0
.global __aeabi_unwind_cpp_pr1
.global __aeabi_unwind_cpp_pr2
raise:
__aeabi_unwind_cpp_pr0:
__aeabi_unwind_cpp_pr1:
__aeabi_unwind_cpp_pr2:
    b       raise
