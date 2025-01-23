/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <kernel/gen_config.h>
#include <elfloader/gen_config.h>

#include "image_start_addr.h"

SECTIONS
{
    . = IMAGE_START_ADDR;
    _text = .;
    .start : {
        *(.text.start)
    }
    .text : {
        *(.text)
    }
    . = ALIGN(16);
    .rodata :
    {
	*(.rodata)
	*(.rodata.*)
        . = ALIGN(16);
        _archive_start = .;
        *(._archive_cpio)
        _archive_end = .;
    }
    . = ALIGN(16);
    .data : {
	*(.data)
	*(.data.*)
    }
    .bss : {
    	. = ALIGN(16);
        _bss = .;
        *(.bss)
        _bss_end = .;
        . = ALIGN(0x1000);
        core_stack_alloc = .;
        . = . + (CONFIG_MAX_NUM_NODES * 1 << 12);
        core_stack_alloc_end = .;
    }
    _end = .;
}
