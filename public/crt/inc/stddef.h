#ifndef _STDDEF_H
#define _STDDEF_H

#ifdef __cplusplus
#define NULL 0L
#else
#define NULL ((void*)0)
#endif

#include <stdint.h>

#if __GNUC__ > 3
#define offsetof(type, member) __builtin_offsetof(type, member)
#else
#define offsetof(type, member) ((size_t)( (char *)&(((type *)0)->member) - (char *)0 ))
#endif

#endif
