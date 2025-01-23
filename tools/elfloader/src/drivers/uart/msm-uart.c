/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <devices_gen.h>
#include <drivers/common.h>
#include <drivers/uart.h>

#include <elfloader_common.h>

#define USR                   0x08
#define UTF                   0x70
#define UNTX                  0x40

#define USR_TXRDY             (1U << 2)
#define USR_TXEMP             (1U << 3)

#define UART_REG(mmio, x) ((volatile uint32_t *)(mmio + (x)))

static int msm_uart_putchar(struct elfloader_device *dev, unsigned int c)
{
    volatile void *mmio = dev->region_bases[0];

    /* Wait for TX fifo to be empty */
    while (!(*UART_REG(mmio, USR) & USR_TXEMP));
    /* Tell the peripheral how many characters to send */
    *UART_REG(mmio, UNTX) = 1;
    /* Write the character into the FIFO */
    *UART_REG(mmio, UTF) = c & 0xff;

    return 0;
}

static int msm_uart_init(struct elfloader_device *dev, UNUSED void *match_data)
{
    uart_set_out(dev);
    return 0;
}

static const struct dtb_match_table msm_uart_matches[] = {
    { .compatible = "qcom,msm-uartdm" },
    { .compatible = NULL /* sentinel */ },
};

static const struct elfloader_uart_ops msm_uart_ops = {
    .putc = &msm_uart_putchar,
};

static const struct elfloader_driver msm_uart = {
    .match_table = msm_uart_matches,
    .type = DRIVER_UART,
    .init = &msm_uart_init,
    .ops = &msm_uart_ops,
};

ELFLOADER_DRIVER(msm_uart);
