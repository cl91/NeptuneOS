#pragma once

#include <string.h>
#include <stdint.h>
#include <nt.h>
#include <sel4/sel4.h>
#include <services.h>
#include <ntdll_syssvc_gen.h>
#include <debug.h>
#include <assert.h>

#define UNIMPLEMENTED
#define DPRINT DbgPrint

#define ERROR_DBGBREAK(...)			\
    do {					\
	DbgPrint("" __VA_ARGS__);		\
	DbgBreakPoint();			\
    } while (0)

#define ASSERT(x)	assert(x)
#define C_ASSERT(x)	compile_assert(NTDLL_COMPILE_ERROR, x)
#define CDECL		__cdecl

#define ROUND_DOWN(x, align)	ALIGN_DOWN_BY(x, align)
#define PAGE_ROUND_DOWN(x)	ROUND_DOWN(x, PAGE_SIZE)
#define ROUND_UP(x, align)	ALIGN_UP_BY(x, align)
#define PAGE_ROUND_UP(x)	ROUND_UP(x, PAGE_SIZE)
#define PAGE_SHIFT		seL4_PageBits

/* From windef.h. We cannot include Win32 headers here. */
typedef unsigned short WORD;
typedef unsigned long DWORD;
typedef ULONG_PTR DWORD_PTR;
typedef CHAR *LPCH, *PCH, *PNZCH, *PSZ;
typedef CONST CHAR *LPCCH, *PCCH, *PCNZCH;
typedef unsigned int UINT;

#define LOBYTE(w)	((BYTE)((DWORD_PTR)(w) & 0xff))
#define HIBYTE(w)	((BYTE)((DWORD_PTR)(w) >> 8))

#define HIWORD(l)	((WORD)(((DWORD_PTR)(l) >> 16) & 0xffff))
#define LOWORD(l)	((WORD)((DWORD_PTR)(l) & 0xffff))
#define MAKELONG(a,b)	((LONG)(((WORD)(a))|(((DWORD)((WORD)(b)))<<16)))

#ifdef _PPC_
#define SWAPD(x) ((((x)&0xff)<<24)|(((x)&0xff00)<<8)|(((x)>>8)&0xff00)|(((x)>>24)&0xff))
#define SWAPW(x) ((((x)&0xff)<<8)|(((x)>>8)&0xff))
#define SWAPQ(x) ((SWAPD((x)&0xffffffff) << 32) | (SWAPD((x)>>32)))
#else
#define SWAPD(x) (x)
#define SWAPW(x) (x)
#define SWAPQ(x) (x)
#endif

/* We cannot include win32 headers so define ULongToPtr here */
static inline void *ULongToPtr(const unsigned long ul)
{
    return (void*)((ULONG_PTR)ul);
}
#define UlongToPtr ULongToPtr

static inline unsigned long PtrToUlong(const void *p)
{
    return ((unsigned long)(ULONG_PTR)p);
}

#define min(a, b) (((a) < (b)) ? (a) : (b))

#define RVA(m, b)	((PVOID)((ULONG_PTR)(b) + (ULONG_PTR)(m)))

/* Use native clang/gcc implementation of structured exception handling */
#include <excpt.h>
#define _SEH2_TRY __try
#define _SEH2_FINALLY __finally
#define _SEH2_EXCEPT(...) __except(__VA_ARGS__)
#define _SEH2_END
#define _SEH2_GetExceptionInformation() (GetExceptionInformation())
#define _SEH2_GetExceptionCode() (GetExceptionCode())
#define _SEH2_AbnormalTermination() (AbnormalTermination())
#define _SEH2_YIELD(STMT_) STMT_
#define _SEH2_LEAVE __leave
#define _SEH2_VOLATILE

/* Defined in winbase.h. We cannot include Win32 headers here */
#define EXCEPTION_NONCONTINUABLE_EXCEPTION ((DWORD)0xC0000025)

#define SharedUserData ((KUSER_SHARED_DATA *CONST) KUSER_SHARED_DATA_CLIENT_ADDR)
