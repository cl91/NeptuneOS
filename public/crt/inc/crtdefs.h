/**
 * This file has no copyright assigned and is placed in the Public Domain.
 * This file is part of the w64 mingw-runtime package.
 * No warranty is given; refer to the file DISCLAIMER within this package.
 */

#ifndef _INC_CRTDEFS
#define _INC_CRTDEFS

#ifndef _In_
#define _In_
#endif

#ifndef _Out_
#define _Out_
#endif

#ifndef _Inout_
#define _Inout_
#endif

#ifdef _USE_32BIT_TIME_T
#ifdef _WIN64
#error You cannot use 32-bit time_t (_USE_32BIT_TIME_T) with _WIN64
#undef _USE_32BIT_TIME_T
#endif
#else
#if _INTEGRAL_MAX_BITS < 64
#define _USE_32BIT_TIME_T
#endif
#endif

#undef _CRT_PACKING
#define _CRT_PACKING 8
#pragma pack(push,_CRT_PACKING)


/** Properties ***************************************************************/

#ifndef _CRT_STRINGIZE
#define __CRT_STRINGIZE(_Value) #_Value
#define _CRT_STRINGIZE(_Value) __CRT_STRINGIZE(_Value)
#endif

#ifndef _CRT_DEFER_MACRO
#define _CRT_DEFER_MACRO(M,...) M(__VA_ARGS__)
#endif

#ifndef _CRT_WIDE
#define __CRT_WIDE(_String) L ## _String
#define _CRT_WIDE(_String) __CRT_WIDE(_String)
#endif

#ifndef _W64
 #if !defined(_midl) && defined(_X86_) && _MSC_VER >= 1300
  #define _W64 __w64
 #else
  #define _W64
 #endif
#endif

#ifndef _CRTIMP
 #ifdef CRTDLL /* Defined for ntdll, crtdll, msvcrt, etc */
  #define _CRTIMP
 #elif defined(_DLL)
  #define _CRTIMP __declspec(dllimport)
 #else /* !CRTDLL && !_DLL */
  #define _CRTIMP
 #endif /* CRTDLL || _DLL */
#endif /* !_CRTIMP */

#ifndef _CRTIMP_ALT
 #ifdef _DLL
  #ifdef _CRT_ALTERNATIVE_INLINES
   #define _CRTIMP_ALT
  #else
   #define _CRTIMP_ALT _CRTIMP
   #define _CRT_ALTERNATIVE_IMPORTED
  #endif
 #else
  #define _CRTIMP_ALT
 #endif
#endif

#ifndef _CRTDATA
 #ifdef _M_CEE_PURE
  #define _CRTDATA(x) x
 #else
  #define _CRTDATA(x) _CRTIMP x
 #endif
#endif

#ifndef _CRTIMP2
 #define _CRTIMP2 _CRTIMP
#endif

#ifndef _CRTIMP_PURE
 #define _CRTIMP_PURE _CRTIMP
#endif

#ifndef _CRTIMP_ALTERNATIVE
 #define _CRTIMP_ALTERNATIVE _CRTIMP
 #define _CRT_ALTERNATIVE_IMPORTED
#endif

#ifndef _CRTIMP_NOIA64
 #ifdef __ia64__
  #define _CRTIMP_NOIA64
 #else
  #define _CRTIMP_NOIA64 _CRTIMP
 #endif
#endif

#ifndef _MRTIMP2
 #define _MRTIMP2  _CRTIMP
#endif

#ifndef _MCRTIMP
 #define _MCRTIMP _CRTIMP
#endif

#ifndef _PGLOBAL
 #define _PGLOBAL
#endif

#ifndef _AGLOBAL
 #define _AGLOBAL
#endif

#ifndef _CONST_RETURN
 #define _CONST_RETURN
#endif

#ifndef UNALIGNED
#if defined(__ia64__) || defined(__x86_64) || defined(__arm__)
#define UNALIGNED __unaligned
#else
#define UNALIGNED
#endif
#endif

#ifndef _CRT_ALIGN
#if defined (__midl) || defined(__WIDL__)
#define _CRT_ALIGN(x)
#elif defined(_MSC_VER)
#define _CRT_ALIGN(x) __declspec(align(x))
#else
#define _CRT_ALIGN(x) __attribute__ ((aligned(x)))
#endif
#endif

#ifndef _CRTNOALIAS
#define _CRTNOALIAS
#endif

#ifndef _CRTRESTRICT
#define _CRTRESTRICT
#endif

#ifndef __CRTDECL
#define __CRTDECL __cdecl
#endif

#ifndef _CRT_UNUSED
#define _CRT_UNUSED(x) (void)x
#endif

#ifndef _CONST_RETURN
#ifdef __cplusplus
#define _CONST_RETURN const
#define _CRT_CONST_CORRECT_OVERLOADS
#else
#define _CONST_RETURN
#endif
#endif

#define __crt_typefix(ctype)


/** Deprecated ***************************************************************/

#ifdef __GNUC__
#define _CRT_DEPRECATE_TEXT(_Text) __attribute__ ((deprecated))
#elif defined(_MSC_VER)
#define _CRT_DEPRECATE_TEXT(_Text) __declspec(deprecated(_Text))
#else
#define _CRT_DEPRECATE_TEXT(_Text)
#endif

#ifndef __STDC_WANT_SECURE_LIB__
#define __STDC_WANT_SECURE_LIB__ 1
#endif

#ifndef _CRT_INSECURE_DEPRECATE
# ifdef _CRT_SECURE_NO_DEPRECATE
#  define _CRT_INSECURE_DEPRECATE(_Replacement)
# else
#  define _CRT_INSECURE_DEPRECATE(_Replacement) \
    _CRT_DEPRECATE_TEXT("This may be unsafe, Try " #_Replacement " instead!")
# endif
#endif

#ifndef _CRT_INSECURE_DEPRECATE_CORE
# ifdef _CRT_SECURE_NO_DEPRECATE_CORE
#  define _CRT_INSECURE_DEPRECATE_CORE(_Replacement)
# else
#  define _CRT_INSECURE_DEPRECATE_CORE(_Replacement) \
    _CRT_DEPRECATE_TEXT("This may be unsafe, Try " #_Replacement " instead! Enable _CRT_SECURE_NO_DEPRECATE to avoid thie warning.")
# endif
#endif

#ifndef _CRT_NONSTDC_DEPRECATE
# ifdef _CRT_NONSTDC_NO_DEPRECATE
#  define _CRT_NONSTDC_DEPRECATE(_Replacement)
# else
#  define _CRT_NONSTDC_DEPRECATE(_Replacement) \
    _CRT_DEPRECATE_TEXT("Deprecated POSIX name, Try " #_Replacement " instead!")
# endif
#endif

#ifndef _CRT_INSECURE_DEPRECATE_MEMORY
#define _CRT_INSECURE_DEPRECATE_MEMORY(_Replacement)
#endif

#ifndef _CRT_INSECURE_DEPRECATE_GLOBALS
#define _CRT_INSECURE_DEPRECATE_GLOBALS(_Replacement)
#endif

#ifndef _CRT_MANAGED_HEAP_DEPRECATE
#define _CRT_MANAGED_HEAP_DEPRECATE
#endif

#ifndef _CRT_OBSOLETE
#define _CRT_OBSOLETE(_NewItem)
#endif

#ifndef _CRT_JIT_INTRINSIC
#define _CRT_JIT_INTRINSIC
#endif


/** Constants ****************************************************************/

#define _ARGMAX 100

#ifndef _TRUNCATE
#define _TRUNCATE ((size_t)-1)
#endif


#if defined(_PREFAST_) && defined(_PFT_SHOULD_CHECK_RETURN)
#define _Check_return_opt_ _Check_return_
#else
#define _Check_return_opt_
#endif

#if defined(_PREFAST_) && defined(_PFT_SHOULD_CHECK_RETURN_WAT)
#define _Check_return_wat_ _Check_return_
#else
#define _Check_return_wat_
#endif

#pragma pack(pop)

#endif /* !_INC_CRTDEFS */
