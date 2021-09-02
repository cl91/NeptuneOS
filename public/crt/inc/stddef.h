/**
 * This file has no copyright assigned and is placed in the Public Domain.
 * This file is part of the w64 mingw-runtime package.
 * No warranty is given; refer to the file DISCLAIMER within this package.
 */

#include <crtdefs.h>

#ifndef _INC_STDDEF
#define _INC_STDDEF

#ifdef __cplusplus
extern "C" {
#endif

#include <errno.h>

  _CRTIMP extern unsigned long __cdecl __threadid(void);
#define _threadid (__threadid())
  _CRTIMP extern uintptr_t __cdecl __threadhandle(void);

#ifdef __cplusplus
}
#endif

/* Offset of member MEMBER in a struct of type TYPE. */
#ifndef offsetof
#if defined(__GNUC__) || defined(__clang__) || defined(_CRT_USE_BUILTIN_OFFSETOF)
# define offsetof(TYPE,MEMBER) __builtin_offsetof(TYPE,MEMBER)
#else
# ifdef __cplusplus
#  ifdef _WIN64
#   define offsetof(TYPE,MEMBER) ((::size_t)(ptrdiff_t)&reinterpret_cast<const volatile char&>((((TYPE*)0)->MEMBER)))
#  else
#   define offsetof(TYPE,MEMBER) ((::size_t)&reinterpret_cast<const volatile char&>((((TYPE*)0)->MEMBER)))
#  endif
# else
#  ifdef _WIN64
#   define offsetof(TYPE,MEMBER) ((size_t)(ptrdiff_t)&(((TYPE*)0)->MEMBER))
#  else
#   define offsetof(TYPE,MEMBER) ((size_t)&(((TYPE*)0)->MEMBER))
#  endif
# endif
#endif
#endif /* !offsetof */

#endif	/* _INC_STDDEF */
