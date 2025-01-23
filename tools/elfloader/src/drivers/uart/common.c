/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 * Copyright 2021, HENSOLDT Cyber
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <devices_gen.h>
#include <drivers/uart.h>
#include <elfloader_common.h>

static struct elfloader_device *uart_out = NULL;


void uart_set_out(struct elfloader_device *out)
{
    if (out->drv->type != DRIVER_UART) {
        return;
    }
    uart_out = out;
}

volatile void *uart_get_mmio(void)
{
    if (uart_out == NULL) {
        return NULL;
    }
    return uart_out->region_bases[0];
}

WEAK int plat_console_putchar(unsigned int c)
{
    if (uart_out == NULL) {
        return 0;
    }

    /* Currently no driver really implements a return code for putc(), they all
     * return 0 unconditionally. So we ignore it here completely. To comply with
     * UART terminal behavior, we print a '\r' (CR) before every '\n' (LF).
     */
    if ('\n' == c) {
        (void)dev_get_uart(uart_out)->putc(uart_out, '\r');
    }

    (void)dev_get_uart(uart_out)->putc(uart_out, c);

    return 0;
}
