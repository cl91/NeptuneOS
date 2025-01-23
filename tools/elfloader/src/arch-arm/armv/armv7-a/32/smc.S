/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <assembler.h>

.text

BEGIN_FUNC(smc)
    .arch_extension sec
    stmfd    sp!, {r3-r11, lr}
    dsb
    smc #0
    ldmfd    sp!, {r3-r11, pc}
END_FUNC(smc)

BEGIN_FUNC(psci_func)
    .arch_extension sec
    stmfd    sp!, {r3-r11, lr}
    dsb
    smc #0
    ldmfd    sp!, {r3-r11, pc}
END_FUNC(psci_func)


