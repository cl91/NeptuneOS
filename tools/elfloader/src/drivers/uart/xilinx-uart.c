/*
 * Copyright 2017, DornerWorks
 * Copyright 2019, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
/*
 * This data was produced by DornerWorks, Ltd. of Grand Rapids, MI, USA under
 * a DARPA SBIR, Contract Number D16PC00107.
 *
 * Approved for Public Release, Distribution Unlimited.
 */

#include <devices_gen.h>
#include <drivers/common.h>
#include <drivers/uart.h>

#include <elfloader_common.h>

/*
 * UART Hardware Constants
 */
#define XUARTPS_CR             0x00
#define XUARTPS_SR             0x2C
#define XUARTPS_FIFO           0x30

#define XUARTPS_SR_TXEMPTY     (1U << 3)

#define XUARTPS_CR_TX_EN       (1U << 4)
#define XUARTPS_CR_TX_DIS      (1U << 5)


#define UART_REG(mmio, x) ((volatile uint32_t *)(mmio + (x)))

static int xilinx_uart_putchar(struct elfloader_device *dev, unsigned int c)
{
    volatile void *mmio = dev->region_bases[0];

    /* Wait to be able to transmit. */
    while (!(*UART_REG(mmio, XUARTPS_SR) & XUARTPS_SR_TXEMPTY));

    /* Transmit. */
    *UART_REG(mmio, XUARTPS_FIFO) = c;

    return 0;
}

static int xilinx_uart_init(struct elfloader_device *dev, UNUSED void *match_data)
{
    volatile void *mmio = dev->region_bases[0];
    uint32_t v = *UART_REG(mmio, XUARTPS_CR);
    v |= XUARTPS_CR_TX_EN;
    v &= ~XUARTPS_CR_TX_DIS;
    *UART_REG(mmio, XUARTPS_CR) = v;

    uart_set_out(dev);
    return 0;
}

static const struct dtb_match_table xilinx_uart_matches[] = {
    { .compatible = "xlnx,xuartps" },
    { .compatible = NULL /* sentinel */ },
};

static const struct elfloader_uart_ops xilinx_uart_ops = {
    .putc = &xilinx_uart_putchar,
};

static const struct elfloader_driver xilinx_uart = {
    .match_table = xilinx_uart_matches,
    .type = DRIVER_UART,
    .init = &xilinx_uart_init,
    .ops = &xilinx_uart_ops,
};

ELFLOADER_DRIVER(xilinx_uart);
