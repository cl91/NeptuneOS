/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <devices_gen.h>
#include <drivers/common.h>
#include <drivers/uart.h>

#include <elfloader_common.h>

#define ULCON       0x0000 /* line control */
#define UCON        0x0004 /*control */
#define UFCON       0x0008 /* fifo control */
#define UMCON       0x000C /* modem control */
#define UTRSTAT     0x0010 /* TX/RX status */
#define UERSTAT     0x0014 /* RX error status */
#define UFSTAT      0x0018 /* FIFO status */
#define UMSTAT      0x001C /* modem status */
#define UTXH        0x0020 /* TX buffer */
#define URXH        0x0024 /* RX buffer */
#define UBRDIV      0x0028 /* baud rate divisor */
#define UFRACVAL    0x002C /* divisor fractional value */
#define UINTP       0x0030 /* interrupt pending */
#define UINTSP      0x0034 /* interrupt source pending */
#define UINTM       0x0038 /* interrupt mask */

#define UART_REG(mmio, x) ((volatile uint32_t *)(mmio + (x)))

/* ULCON */
#define WORD_LENGTH_8   (3<<0)

/* UTRSTAT */
#define TX_EMPTY        (1<<2)
#define TXBUF_EMPTY     (1<<1)

static int exynos_uart_putchar(struct elfloader_device *dev, unsigned int c)
{
    volatile void *mmio = dev->region_bases[0];

    /* Wait until UART ready for the next character. */
    while (!(*UART_REG(mmio, UTRSTAT) & TXBUF_EMPTY));

    /* Put in the register to be sent*/
    *UART_REG(mmio, UTXH) = (c & 0xff);

    return 0;
}

static int exynos_uart_init(struct elfloader_device *dev, UNUSED void *match_data)
{
    uart_set_out(dev);
    return 0;
}

static const struct dtb_match_table exynos_uart_matches[] = {
    { .compatible = "samsung,exynos4210-uart" },
    { .compatible = NULL /* sentinel */ },
};

static const struct elfloader_uart_ops exynos_uart_ops = {
    .putc = &exynos_uart_putchar,
};

static const struct elfloader_driver exynos_uart = {
    .match_table = exynos_uart_matches,
    .type = DRIVER_UART,
    .init = &exynos_uart_init,
    .ops = &exynos_uart_ops,
};

ELFLOADER_DRIVER(exynos_uart);
