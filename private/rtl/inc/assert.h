#pragma once

#ifdef CONFIG_DEBUG_BUILD

void _assert_fail(
    const char  *assertion,
    const char  *file,
    unsigned int line,
    const char  *function
);

#define assert(expr) \
    if(!(expr)) _assert_fail(#expr, __FILE__, __LINE__, __FUNCTION__)

#else

#define assert(expr)

#endif	/* CONFIG_DEBUG_BUILD */
