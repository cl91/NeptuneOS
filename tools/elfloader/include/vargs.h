/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

/*
 Authors: Ben Leslie
*/
/*
  Implementation based on C99 Section 7.15 Variable arguments
*/

#pragma once

typedef __builtin_va_list va_list;

#define va_arg(ap, type) __builtin_va_arg(ap, type)
#define va_copy(dest, src) __builtin_va_copy(dest, src)
#define va_end(ap) __builtin_va_end(ap)
#define va_start(ap, parmN) __builtin_va_start(ap, parmN)

