/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 * Copyright 2020, HENSOLDT Cyber GmbH
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <devices_gen.h>
#include <drivers/common.h>
#include <drivers/uart.h>

#include <elfloader_common.h>

#define UART_TRANSMIT     0x40
#define UART_CONTROL1     0x80
#define UART_CONTROL2     0x84
#define UART_CONTROL3     0x88
#define UART_CONTROL4     0x8C
#define UART_FIFO_CTRL    0x90
#define UART_STAT1        0x94
#define UART_STAT2        0x98

/* Transmit buffer FIFO empty. */
#define TXFE            (1U << 14)

#define UART_REG(mmio, x) ((volatile uint32_t *)(mmio + (x)))

static int imx_uart_putchar(struct elfloader_device *dev, unsigned int c)
{
    volatile void *mmio = dev->region_bases[0];

    /* Wait to be able to transmit. */
    while (!(*UART_REG(mmio, UART_STAT2) & TXFE));

    /* Transmit. */
    *UART_REG(mmio, UART_TRANSMIT) = c;

    return 0;
}

static int imx_uart_init(struct elfloader_device *dev, UNUSED void *match_data)
{
    uart_set_out(dev);
    return 0;
}

static const struct dtb_match_table imx_uart_matches[] = {
    { .compatible = "fsl,imx6q-uart" },
    { .compatible = "fsl,imx6sx-uart" },
    { .compatible = NULL /* sentinel */ },
};

static const struct elfloader_uart_ops imx_uart_ops = {
    .putc = &imx_uart_putchar,
};

static const struct elfloader_driver imx_uart = {
    .match_table = imx_uart_matches,
    .type = DRIVER_UART,
    .init = &imx_uart_init,
    .ops = &imx_uart_ops,
};

ELFLOADER_DRIVER(imx_uart);
