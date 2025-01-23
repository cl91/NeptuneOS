/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <elfloader_common.h>
#include <devices_gen.h>
#include <drivers/common.h>
#include <drivers/uart.h>

#include <printf.h>
#include <types.h>

#define UTHR 0x00 /* UART Transmit Holding Register */
#define ULSR 0x14 /* UART Line Status Register */
#define ULSR_THRE (1 << 5) /* Transmit Holding Register Empty */

#define UART_REG(mmio, x) ((volatile uint32_t *)(((uintptr_t)mmio) + (x)))

static int uart_8250_putchar(struct elfloader_device *dev, unsigned int c)
{
    volatile void *mmio = dev->region_bases[0];

    /* Wait until UART ready for the next character. */
    while ((*UART_REG(mmio, ULSR) & ULSR_THRE) == 0);

    /* Add character to the buffer. */
    *UART_REG(mmio, UTHR) = c;

    return 0;
}

static int uart_8250_init(struct elfloader_device *dev,
                          UNUSED void *match_data)
{
    uart_set_out(dev);
    return 0;
}

static const struct dtb_match_table uart_8250_matches[] = {
    { .compatible = "nvidia,tegra20-uart" },
    { .compatible = "ti,omap3-uart" },
    { .compatible = "snps,dw-apb-uart" },
    { .compatible = NULL /* sentinel */ },
};

static const struct elfloader_uart_ops uart_8250_ops = {
    .putc = &uart_8250_putchar,
};

static const struct elfloader_driver uart_8250 = {
    .match_table = uart_8250_matches,
    .type = DRIVER_UART,
    .init = &uart_8250_init,
    .ops = &uart_8250_ops,
};

ELFLOADER_DRIVER(uart_8250);
