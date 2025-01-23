/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

 #include <assembler.h>
 #include <mode/assembler.h>

.text

.extern invalid_vector_entry
.extern el1_sync

.macro ventry label
.align 7
    b       \label
.endm

.align 12
BEGIN_FUNC(arm_vector_table)
    ventry  invalid_vector_entry           // Synchronous EL1t
    ventry  invalid_vector_entry           // IRQ EL1t
    ventry  invalid_vector_entry           // FIQ EL1t
    ventry  invalid_vector_entry           // SError EL1t

    ventry  el1_sync                       // Synchronous EL1h
    ventry  invalid_vector_entry           // IRQ EL1h
    ventry  invalid_vector_entry           // FIQ EL1h
    ventry  invalid_vector_entry           // SError EL1h

    ventry  invalid_vector_entry           // Synchronous 64-bit EL0
    ventry  invalid_vector_entry           // IRQ 64-bit EL0
    ventry  invalid_vector_entry           // FIQ 64-bit EL0
    ventry  invalid_vector_entry           // SError 64-bit EL0

    ventry  invalid_vector_entry           // Synchronous 32-bit EL0
    ventry  invalid_vector_entry           // IRQ 32-bit EL0
    ventry  invalid_vector_entry           // FIQ 32-bit EL0
    ventry  invalid_vector_entry           // SError 32-bit EL0
END_FUNC(arm_vector_table)
