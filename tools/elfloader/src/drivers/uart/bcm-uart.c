/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <devices_gen.h>
#include <drivers/common.h>
#include <drivers/uart.h>

#include <elfloader_common.h>

/* When DLAB=1, MU_IO is a baud rate register.
 * Otherwise, write to TX, read to RX */
#define MU_IO       0x00
/* When DLAB=1, MU_IIR is a baud rate register.
 * Otherwise IRQ enable */
#define MU_IIR      0x04
#define MU_IER      0x08
#define MU_LCR      0x0C
#define MU_MCR      0x10
#define MU_LSR      0x14
#define MU_MSR      0x18
#define MU_SCRATCH  0x1C
#define MU_CNTL     0x20

/* This bit is set if the transmit FIFO can accept at least one byte.*/
#define MU_LSR_TXEMPTY  BIT(5)
/* This bit is set if the transmit FIFO is empty and the
 * transmitter is idle. (Finished shifting out the last bit). */
#define MU_LSR_TXIDLE   BIT(6)

#define MU_LCR_DLAB     BIT(7)
#define MU_LCR_BREAK    BIT(6)
#define MU_LCR_DATASIZE BIT(0)

#define UART_REG(mmio, x) ((volatile uint32_t *)((mmio) + (x)))

static int bcm2835_uart_putchar(struct elfloader_device *dev, unsigned int c)
{
    volatile void *mmio = dev->region_bases[0];

    /* Wait until UART ready for the next character. */
    while (!(*UART_REG(mmio, MU_LSR) & MU_LSR_TXIDLE));

    /* Put in the register to be sent*/
    *UART_REG(mmio, MU_IO) = (c & 0xff);

    return 0;
}

static int bcm2835_uart_init(struct elfloader_device *dev, UNUSED void *match_data)
{
    uart_set_out(dev);
    return 0;
}

static const struct dtb_match_table bcm2835_uart_matches[] = {
    { .compatible = "brcm,bcm2835-aux-uart" },
    { .compatible = NULL /* sentinel */ },
};

static const struct elfloader_uart_ops bcm2835_uart_ops = {
    .putc = &bcm2835_uart_putchar,
};

static const struct elfloader_driver bcm2835_uart = {
    .match_table = bcm2835_uart_matches,
    .type = DRIVER_UART,
    .init = &bcm2835_uart_init,
    .ops = &bcm2835_uart_ops,
};

ELFLOADER_DRIVER(bcm2835_uart);
