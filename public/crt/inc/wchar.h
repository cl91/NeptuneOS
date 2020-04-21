#ifndef _WCHAR_H
#define _WCHAR_H

#ifdef __cplusplus
extern "C" {
#endif

#include <bits/alltypes.h>
#include <stdint.h>

#if L'\0'-1 > 0
#define WCHAR_MAX (0xffffffffu+L'\0')
#define WCHAR_MIN (0+L'\0')
#else
#define WCHAR_MAX (0x7fffffff+L'\0')
#define WCHAR_MIN (-1-0x7fffffff+L'\0')
#endif

#undef WEOF
#define WEOF 0xffffffffU

size_t wcslen (const wchar_t *);

#ifndef __cplusplus
#undef iswdigit
#define iswdigit(a) ((unsigned)(a)-'0') < 10)
#endif

#ifdef __cplusplus
}
#endif

#endif
