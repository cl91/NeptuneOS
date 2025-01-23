/*
 * Copyright 2021, Data61, CSIRO (ABN 41 687 119 230)
 * Copyright 2021, Breakaway Consulting Pty. Ltd.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
/*
 * A simple output only UART driver for the NXP i.MX Low Power UART.
 *
 * Technical Reference:
 *   i.MX 8DualX/8DualXPlus/8QuadXPlus Applications Processor Reference Manual
 *   Revision 0 (IMX8DQXPRM.pdf)
 *   Chapter 16.13 (page 7908)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <devices_gen.h>
#include <drivers/common.h>
#include <drivers/uart.h>

#include <elfloader_common.h>

#define STAT 0x14
#define TRANSMIT 0x1c

#define STAT_TDRE (1 << 23)

#define UART_REG(mmio, x) ((volatile uint32_t *)(mmio + (x)))

static int imx_lpuart_putchar(struct elfloader_device *dev, unsigned int c)
{
    volatile void *mmio = dev->region_bases[0];

    /* Wait to be able to transmit. */
    while (!(*UART_REG(mmio, STAT) & STAT_TDRE)) { }

    *UART_REG(mmio, TRANSMIT) = c;

    return 0;
}

static int imx_lpuart_init(struct elfloader_device *dev, UNUSED void *match_data)
{
    uart_set_out(dev);
    return 0;
}

static const struct dtb_match_table imx_lpuart_matches[] = {
    { .compatible = "fsl,imx8qxp-lpuart" },
    { .compatible = NULL /* sentinel */ },
};

static const struct elfloader_uart_ops imx_lpuart_ops = {
    .putc = &imx_lpuart_putchar,
};

static const struct elfloader_driver imx_lpuart = {
    .match_table = imx_lpuart_matches,
    .type = DRIVER_UART,
    .init = &imx_lpuart_init,
    .ops = &imx_lpuart_ops,
};

ELFLOADER_DRIVER(imx_lpuart);
