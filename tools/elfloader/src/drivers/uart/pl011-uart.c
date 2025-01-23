/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <devices_gen.h>
#include <drivers/common.h>
#include <drivers/uart.h>

#include <elfloader_common.h>

#define UARTDR      0x000
#define UARTFR      0x018
#define UARTFR_TXFF (1 << 5)

#define UART_REG(mmio, x) ((volatile uint32_t *)(mmio + (x)))

int pl011_uart_putchar(struct elfloader_device *dev, unsigned int c)
{
    volatile void *mmio = dev->region_bases[0];

    /* Wait until UART ready for the next character. */
    while ((*UART_REG(mmio, UARTFR) & UARTFR_TXFF) != 0);

    /* Add character to the buffer. */
    *UART_REG(mmio, UARTDR) = (c & 0xff);

    return 0;
}

static int pl011_uart_init(struct elfloader_device *dev, UNUSED void *match_data)
{
    uart_set_out(dev);
    return 0;
}

static const struct dtb_match_table pl011_uart_matches[] = {
    { .compatible = "arm,pl011" },
    { .compatible = NULL /* sentinel */ },
};

static const struct elfloader_uart_ops pl011_uart_ops = {
    .putc = &pl011_uart_putchar,
};

static const struct elfloader_driver pl011_uart = {
    .match_table = pl011_uart_matches,
    .type = DRIVER_UART,
    .init = &pl011_uart_init,
    .ops = &pl011_uart_ops,
};

ELFLOADER_DRIVER(pl011_uart);
