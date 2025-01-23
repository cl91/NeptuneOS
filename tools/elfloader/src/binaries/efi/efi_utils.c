/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <binaries/efi/efi.h>

int efi_guideq(efi_guid_t a, efi_guid_t b)
{
    for (unsigned int i = 0; i < sizeof(efi_guid_t); i++) {
        if (a.b[i] != b.b[i])
            return 0;
    }

    return 1;
}

efi_boot_services_t *get_efi_boot_services(void)
{
    return ((efi_boot_services_t *)(__efi_system_table->boottime));
}
