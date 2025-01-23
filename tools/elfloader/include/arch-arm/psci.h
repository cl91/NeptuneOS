/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#pragma once


#define PSCI_SUCCESS                 0
#define PSCI_NOT_SUPPORTED          -1
#define PSCI_INVALID_PARAMETERS     -2
#define PSCI_DENIED                 -3
#define PSCI_ALREADY_ON             -4
#define PSCI_ON_PENDING             -5
#define PSCI_INTERNAL_FAILURE       -6
#define PSCI_NOT_PRESETN            -7
#define PSCI_DISABLED               -8
#define PSCI_INVALID_ADDRESS        -9

#define PSCI_METHOD_SMC             1
#define PSCI_METHOD_HVC             2

int psci_version(void);
int psci_cpu_suspend(int power_state, unsigned long entry_point,
                     unsigned long context_id);
/* this function does not return when successful */
int psci_cpu_off(void);
int psci_cpu_on(unsigned long target_cpu, unsigned long entry_point,
                unsigned long context_id);
int psci_system_reset(void);
