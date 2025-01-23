/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <devices_gen.h>
#include <drivers/common.h>
#include <drivers/uart.h>

#include <elfloader_common.h>

#define UART_WFIFO  0x0
#define UART_STATUS 0xC
#define UART_TX_FULL        BIT(21)
#define UART_REG(mmio, x) ((volatile uint32_t *)(mmio + (x)))

static int meson_uart_putchar(struct elfloader_device *dev, unsigned int c)
{
    volatile void *mmio = dev->region_bases[0];

    /* Wait to be able to transmit. */
    while ((*UART_REG(mmio, UART_STATUS) & UART_TX_FULL));

    /* Transmit. */
    *UART_REG(mmio, UART_WFIFO) = c;

    return 0;
}

static int meson_uart_init(struct elfloader_device *dev, UNUSED void *match_data)
{
    uart_set_out(dev);
    return 0;
}

static const struct dtb_match_table meson_uart_matches[] = {
    { .compatible = "amlogic,meson-gx-uart" },
    { .compatible = NULL /* sentinel */ },
};

static const struct elfloader_uart_ops meson_uart_ops = {
    .putc = &meson_uart_putchar,
};

static const struct elfloader_driver meson_uart = {
    .match_table = meson_uart_matches,
    .type = DRIVER_UART,
    .init = &meson_uart_init,
    .ops = &meson_uart_ops,
};

ELFLOADER_DRIVER(meson_uart);
