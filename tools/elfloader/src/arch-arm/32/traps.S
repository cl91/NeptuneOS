/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

 #include <assembler.h>
 #include <mode/assembler.h>

 #define ABORTSTACK_SIZE 4096
.text

.align 12
BEGIN_FUNC(arm_vector_table)
    ldr pc, =invalid_vector_entry
    ldr pc, =invalid_vector_entry
    ldr pc, =invalid_vector_entry
    ldr pc, =invalid_vector_entry
    ldr pc, =arm_data_abort_exception
    ldr pc, =invalid_vector_entry
    ldr pc, =arm_irq_exception
    ldr pc, =invalid_vector_entry
arm_vector_literals:
.globl arm_vector_literals
.ltorg
END_FUNC(arm_vector_table)

.align 12
/*
 * If any of the following exception happens, then there is something wrong
 * with our code, so abort explicitly:
 * - Undefined Instruction
 * - Supervisor Call
 * - Prefetch Abort
 */
BEGIN_FUNC(invalid_vector_entry)
    adr sp, _abortstack_bottom
    add sp, sp, #ABORTSTACK_SIZE
    bl invalid_exception
END_FUNC(invalid_vector_entry)

/*
 * Otherwise, we may receive some exceptions due to bootloader inappropriate
 * initialization, simply ignore them:
 * - Aborting instruction only if imprecise
 * - IRQ next instruction
 */
BEGIN_FUNC(arm_data_abort_exception)
    adr sp, _abortstack_bottom
    add sp, sp, #ABORTSTACK_SIZE

    /* Store CPSR and LR on stack */
    sub lr, lr, #8
    srsdb sp!, #PMODE_ABORT

    mrc p15, 0, r0, c5, c0, 0    /* Get data fault status register. */
    mrc p15, 0, r1, c6, c0, 0    /* Get fault address register. */

    bl check_data_abort_exception

    /* Jump to NextPC and restore user CPSR */
    rfeia sp!
END_FUNC(arm_data_abort_exception)

BEGIN_FUNC(arm_irq_exception)
    adr sp, _abortstack_bottom
    add sp, sp, #ABORTSTACK_SIZE

    /* Store CPSR and LR on stack */
    sub lr, lr, #4
    srsdb sp!, #PMODE_IRQ

    bl valid_exception

    /* Jump to NextPC and restore CPSR */
    rfeia sp!
END_FUNC(arm_irq_exception)

.align 3
_abortstack_bottom:
.space ABORTSTACK_SIZE
_abortstack_top:
