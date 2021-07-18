#pragma once

#ifdef CONFIG_DEBUG_BUILD

#define assert(expr) \
    if(!(expr)) __assert_fail(#expr, __FILE__, __LINE__, __FUNCTION__)

#else

#define assert(expr)

#endif	/* CONFIG_DEBUG_BUILD */
