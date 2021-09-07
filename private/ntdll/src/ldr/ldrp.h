#pragma once

#include <ntdll.h>

#define FORCEINLINE __forceinline

#ifdef _PPC_
#define SWAPD(x) ((((x)&0xff)<<24)|(((x)&0xff00)<<8)|(((x)>>8)&0xff00)|(((x)>>24)&0xff))
#define SWAPW(x) ((((x)&0xff)<<8)|(((x)>>8)&0xff))
#define SWAPQ(x) ((SWAPD((x)&0xffffffff) << 32) | (SWAPD((x)>>32)))
#else
#define SWAPD(x) (x)
#define SWAPW(x) (x)
#define SWAPQ(x) (x)
#endif

/* From windef.h. We cannot include Win32 headers here. */
typedef unsigned short WORD;
typedef unsigned long DWORD;
typedef ULONG_PTR DWORD_PTR;
typedef CHAR *LPCH, *PCH, *PNZCH;
typedef CONST CHAR *LPCCH, *PCCH, *PCNZCH;

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

/* pe.c */
static ULONG NTAPI LdrpRelocateImage(IN PVOID BaseAddress,
				     IN PCCH  LoaderName,
				     IN ULONG Success,
				     IN ULONG Conflict,
				     IN ULONG Invalid);
static ULONG NTAPI LdrpRelocateImageWithBias(IN PVOID BaseAddress,
					     IN LONGLONG AdditionalBias,
					     IN PCCH  LoaderName,
					     IN ULONG Success,
					     IN ULONG Conflict,
					     IN ULONG Invalid);
