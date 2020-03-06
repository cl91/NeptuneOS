#define _Addr int
#define _Int64 long long
#define _Reg int

#if __GNUC__ >= 3
typedef __builtin_va_list va_list;
typedef __builtin_va_list __isoc_va_list;
#else
typedef struct __va_list * va_list;
typedef struct __va_list * __isoc_va_list;
#endif

#ifndef __cplusplus
#ifdef __WCHAR_TYPE__
typedef __WCHAR_TYPE__ wchar_t;
#else
typedef long wchar_t;
#endif
#endif

#if !defined(__cplusplus)
typedef struct { _Alignas(8) long long __ll; long double __ld; } max_align_t;
#elif defined(__GNUC__)
typedef struct { __attribute__((__aligned__(8))) long long __ll; long double __ld; } max_align_t;
#else
typedef struct { alignas(8) long long __ll; long double __ld; } max_align_t;
#endif

typedef long time_t;
typedef long suseconds_t;
