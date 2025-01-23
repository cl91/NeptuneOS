/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <elfloader_common.h>
#include "sbi.h"

int plat_console_putchar(unsigned int c)
{
    sbi_console_putchar(c);
    return 0;
}
