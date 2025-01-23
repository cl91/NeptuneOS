/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 * Copyright 2021, HENSOLDT Cyber
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#pragma once

/*------------------------------------------------------------------------------
 * _Static_assert() is a c11 feature, emulate it for older versions.
 */
#if defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 201112L)
#define compile_assert(name, expr)   _Static_assert(expr, #name);
#else
#define compile_assert(name, expr) \
    typedef int __assert_failed_##name[(expr) ? 1 : -1] __attribute__((unused));
#endif


/*------------------------------------------------------------------------------
 * helper macro that ensure the passed macro gets evaluated first before the
 * concatenation happens. The concat macros even work when a parameter is
 * defined to be empty,
 */
#define _macro_make_string_helper(x)    # x
#define _macro_make_string(x)           _macro_make_string_helper(x)

#define _macro_concat2_helper(x,y)      x ## y
#define _macro_concat2(x,y)             _macro_concat2_helper(x,y)

#define _macro_concat3_helper(x,y,z)    x ## y ## z
#define _macro_concat3(x,y,z)           _macro_concat3_helper(x,y,z)


/*------------------------------------------------------------------------------
 * define basic fixed size integer types
 */
typedef signed char     int8_t;
typedef unsigned char   uint8_t;

typedef signed short    int16_t;
typedef unsigned short  uint16_t;

typedef signed int      int32_t;
typedef unsigned int    uint32_t;


#if defined(__KERNEL_32__)

#define _int64_type         long long
#define _int64_type_fmt     ll  // for printf() formatting and integer suffix

#elif defined(__KERNEL_64__)

#define _int64_type         long
#define _int64_type_fmt     l  // for printf() formatting and integer suffix

#else
#error expecting either __KERNEL_32__ or __KERNEL_64__ to be defined
#endif

compile_assert(valid_int64_type, 8 == sizeof(_int64_type));

typedef signed _int64_type      int64_t;
typedef unsigned _int64_type    uint64_t;

/* helper macros to define 64-bit constants */
#define INT64_C(v)      _macro_concat2(v, _int64_type_fmt)
#define UINT64_C(v)     _macro_concat3(v, _int64_type_fmt, u)

#define UINT32_MAX      (0xffffffff)
#define UINT64_MAX      UINT64_C(0xffffffffffffffff)

/* printf() format specifiers for 64-bit values*/
#define PRId64  _macro_make_string(_macro_concat2(_int64_type_fmt, d))
#define PRIi64  _macro_make_string(_macro_concat2(_int64_type_fmt, i))
#define PRIu64  _macro_make_string(_macro_concat2(_int64_type_fmt, u))
#define PRIx64  _macro_make_string(_macro_concat2(_int64_type_fmt, x))


/*------------------------------------------------------------------------------
 * [u]intmax_t is [u]int64_t on all platform we support so far
 */
typedef int64_t     intmax_t;
typedef uint64_t    uintmax_t;

/* printf() format specifiers for [u]intmax_t */
#define PRIdMAX     PRId64
#define PRIiMAX     PRIi64
#define PRIuMAX     PRIu64
#define PRIxMAX     PRIx64


/*------------------------------------------------------------------------------
 * define [u]intptr_t
 */
#if defined(__KERNEL_32__)

typedef int32_t         intptr_t;
typedef uint32_t        uintptr_t;
#define UINTPTR_MAX     UINT32_MAX
#define _ptr_type_fmt   /* empty */

#elif defined(__KERNEL_64__)

typedef int64_t         intptr_t;
typedef uint64_t        uintptr_t;
#define UINTPTR_MAX     UINT64_MAX
#define _ptr_type_fmt   _int64_type_fmt

#else
#error expecting either __KERNEL_32__ or __KERNEL_64__ to be defined
#endif

/* printf() format specifiers for [u]intptr_t */
#define PRIdPTR  _macro_make_string(_macro_concat2(_ptr_type_fmt, d))
#define PRIiPTR  _macro_make_string(_macro_concat2(_ptr_type_fmt, i))
#define PRIuPTR  _macro_make_string(_macro_concat2(_ptr_type_fmt, u))
#define PRIxPTR  _macro_make_string(_macro_concat2(_ptr_type_fmt, x))

/*------------------------------------------------------------------------------
 * [s]size_t basically follows [u]intptr_t
 */
typedef intptr_t    ssize_t;
typedef uintptr_t   size_t;


/*------------------------------------------------------------------------------
 * word_t is practically an alias for size_t/uintptr_t on the platforms we
 * support so far.
 */
typedef uintptr_t    word_t;
#define WORD_MAX     UINTPTR_MAX

/* printf() format specifiers for word_t */
#define PRId_word   PRIdPTR
#define PRIi_word   PRIiPTR
#define PRIu_word   PRIuPTR
#define PRIx_word   PRIxPTR
