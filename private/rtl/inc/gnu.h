#pragma once

#if defined(__GNUC__) || defined(__clang__)

#define __packed	__attribute__((__packed__))
#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)
#define __aligned(x)	__attribute__((aligned(x)))
#define __section(x)	__attribute__((section(x)))
#define UNUSED		__attribute__((unused))

/* Prevent the compiler from inlining the function */
#define NO_INLINE	__attribute__((noinline))

/* Inform the compiler that the function does not return */
#define NORETURN	__attribute__((__noreturn__))

#else
#error "Use a real compiler you pleb"
#endif
