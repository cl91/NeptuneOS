/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <printf.h>
#include <types.h>
#include <vargs.h>
#include <elfloader_common.h>

/*
 * Maximum space needed to print an integer in any base.
 *
 * We set this to log_2(2**64) + 1 + safety margin ~= 80.
 */
#define MAX_INT_BUFF_SIZE  80

/*
 * Function to process a simple character. "payload" may point
 * to arbitrary state needed by the "write_char" function.
 */
typedef void write_char_fn(
    void *payload,
    int c);

/* Write a NUL-terminated string to the given 'write_char' function. */
static void write_string(
    write_char_fn write_char,
    void *payload,
    const char *str)
{
    for (unsigned int i = 0; str[i] != 0; i++) {
        write_char(payload, str[i]);
    }
}

/*
 * Write the given unsigned number "n" to the given write_char function.
 *
 * We only support bases up to 16.
 */
static void write_num(
    write_char_fn write_char,
    void *payload,
    unsigned int base,
    uintmax_t n)
{
    static const char hex[] = "0123456789abcdef";
    char buff[MAX_INT_BUFF_SIZE];
    unsigned int k = MAX_INT_BUFF_SIZE - 1;

    /* Special case for "0". */
    if (n == 0) {
        write_string(write_char, payload, "0");
        return;
    }

    /* NUL-terminate. */
    buff[k--] = 0;

    /* Generate the number. */
    while (n > 0) {
        buff[k] = hex[n % base];
        n /= base;
        k--;
    }

    /* Print the number. */
    write_string(write_char, payload, &buff[k + 1]);
}

/*
 * Print a printf-style string to the given write_char function.
 */
static void vxprintf(
    write_char_fn write_char,
    void *payload,
    const char *format,
    va_list args)
{
    int escape_mode = 0;
    /* Iterate over the format list. */
    for (unsigned int i = 0; format[i] != 0; i++) {
        /* Handle simple characters. */
        if (!escape_mode && format[i] != '%') {
            write_char(payload, format[i]);
            continue;
        }

        /* Handle the percent escape character. */
        if (format[i] == '%') {
            if (!escape_mode) {
                /* Entering escape mode. */
                escape_mode = 1;
            } else {
                /* Already in escape mode; print a percent. */
                write_char(payload, format[i]);
                escape_mode = 0;
            }
            continue;
        }

        /* Handle the modifier. */
        switch (format[i]) {
        /* Ignore printf modifiers we don't support. */
        case '0':
        case '1':
        case '2':
        case '3':
        case '4':
        case '5':
        case '6':
        case '7':
        case '8':
        case '9':
        case '-':
        case '.':
            break;

        /* String. */
        case 's':
            write_string(write_char, payload, va_arg(args, char *));
            escape_mode = 0;
            break;

        /* Pointers. */
        case 'p':
            write_num(write_char, payload, 16, (uintptr_t)va_arg(args, void *));
            escape_mode = 0;
            break;

        /* Hex number. */
        case 'x':
            write_num(write_char, payload, 16, va_arg(args, int));
            escape_mode = 0;
            break;

        /* Decimal number. */
        case 'd':
        case 'u':
            write_num(write_char, payload, 10, va_arg(args, int));
            escape_mode = 0;
            break;

        /* Character. */
        case 'c':
            write_char(payload, va_arg(args, int));
            escape_mode = 0;
            break;

        /* size_t number. */
        case 'z':
            switch (format[++i]) {
            case 'd':
            case 'u':
                write_num(write_char, payload, 10,
                          va_arg(args, size_t));
                break;

            case 'x':
                write_num(write_char, payload, 16,
                          va_arg(args, size_t));
                break;

            default:
                write_char(payload, '?');
            }
            escape_mode = 0;
            break;

        /* Long number. */
        case 'l':
            switch (format[++i]) {
            case 'd':
            case 'u':
                write_num(write_char, payload, 10,
                          va_arg(args, unsigned long));
                break;

            case 'x':
                write_num(write_char, payload, 16,
                          va_arg(args, unsigned long));
                break;

            /* Long Long number. */
            case 'l':
                switch (format[++i]) {
                case 'd':
                case 'u':
                    write_num(write_char, payload, 10,
                              va_arg(args, unsigned long long));
                    break;

                case 'x':
                    write_num(write_char, payload, 16,
                              va_arg(args, unsigned long long));
                    break;

                default:
                    write_char(payload, '?');
                }
                break;

            default:
                write_char(payload, '?');
            }
            escape_mode = 0;
            break;

        /* Unknown. */
        default:
            write_char(payload, '?');
            escape_mode = 0;
            break;
        }
    }
}

/*
 * Simple printf/puts implementation.
 */

typedef struct {
    unsigned int cnt;
} arch_write_char_ctx_t;

static void arch_write_char(
    void *payload,
    int c)
{
    arch_write_char_ctx_t *ctx = payload;

    plat_console_putchar(c);
    /* do do not really know what plat_console_putchar() does effectively, all
     * we do know is that we have given it one character.
     */
    ctx->cnt++;
}

int printf(
    const char *format,
    ...)
{
    arch_write_char_ctx_t ctx = {0};
    va_list args;
    va_start(args, format);
    vxprintf(arch_write_char, &ctx, format, args);
    va_end(args);
    return (int)ctx.cnt;
}

int puts(
    const char *str)
{
    arch_write_char_ctx_t ctx = {0};
    write_string(arch_write_char, &ctx, str);
    arch_write_char(&ctx, '\n');
    return (int)ctx.cnt;
}

/*
 * Simple sprintf implementation.
 */

struct sprintf_payload {
    char *buff;
    int n;
};

static void sprintf_write_char(
    void *payload,
    int c)
{
    struct sprintf_payload *p = (struct sprintf_payload *)payload;
    p->buff[p->n] = c;
    p->n++;
}

int sprintf(
    char *buff,
    const char *format,
    ...)
{
    struct sprintf_payload p = {buff, 0};
    va_list args;
    va_start(args, format);
    vxprintf(sprintf_write_char, &p, format, args);
    va_end(args);
    return p.n;
}
