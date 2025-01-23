/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <abort.h>
#include <elfloader_common.h>
#include <types.h>

#define DFSR_FS_MASK                0x40f
#define DFSR_FS_ASYNC_EXT_ABORT     0x406
#define DFSR_FS_ASYNC_PARITY_ERR    0x408

void check_data_abort_exception(word_t dfsr, UNUSED word_t dfar)
{
    //* Check if the data exception is asynchronous external abort or
    //* asynchronous parity error on memory access */
    word_t fs = dfsr & DFSR_FS_MASK;

    if ((fs == DFSR_FS_ASYNC_EXT_ABORT) ||
        (fs == DFSR_FS_ASYNC_PARITY_ERR)) {
        return;
    }
    abort();
}

void valid_exception(void)
{

}

void invalid_exception(void)
{
    abort();
}
