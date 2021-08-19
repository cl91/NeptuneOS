#pragma once

#define STATUS_ASSERT_FAILED	(0xc04500af)

#ifdef CONFIG_DEBUG_BUILD

#define assert(expr)							\
    if(!(expr)) __assert_fail(#expr, __FILE__, __LINE__, __FUNCTION__)
#define assert_ret(expr)			\
    if (!(expr)) return STATUS_ASSERT_FAILED;

#else

#define assert(expr)
#define assert_ret(expr)

#endif	/* CONFIG_DEBUG_BUILD */
