#pragma once

#ifdef __i386__
#ifndef _M_IX86
#define _M_IX86
#endif
#endif

#ifdef __x86_64__
#ifndef _M_AMD64
#define _M_AMD64
#define _WIN64
#endif
#endif

#ifdef __aarch64__
#ifndef _M_ARM64
#define _M_ARM64
#define _WIN64
#endif
#endif

#include <stdint.h>

#ifdef _M_IX86
#define FASTCALL __fastcall
#define NTAPI __stdcall
#else
#define FASTCALL
#define NTAPI
#endif

#define STDAPICALLTYPE		__stdcall

#define DECLSPEC_IMPORT		__declspec(dllimport)

#define DECLSPEC_NORETURN	__attribute__((noreturn))
#define DECLSPEC_DEPRECATED	__attribute__((deprecated))
#define DEPRECATED(x)		__attribute__((deprecated(x)))
#define FORCEINLINE		static inline __attribute__((always_inline))
#define __ALIGNED(x)		__attribute__((aligned(x)))
#define DECLSPEC_ALIGN(x)	__ALIGNED(x)

/* 64 bytes seem to be a safe assumption for most modern Intel and ARM64 systems. */
#define SYSTEM_CACHE_ALIGNMENT_SIZE 64

#define DECLSPEC_CACHEALIGN DECLSPEC_ALIGN(SYSTEM_CACHE_ALIGNMENT_SIZE)

#if !defined(_NTSYSTEM_) && !defined(_NTOSKRNL_) && !defined(_NTPSX_)
#define NTSYSAPI	DECLSPEC_IMPORT
#define NTSYSCALLAPI	DECLSPEC_IMPORT
#else
#define NTSYSAPI
#define NTSYSCALLAPI
#endif

#define IN
#define OUT
#define OPTIONAL

#define _ANONYMOUS_UNION
#define _ANONYMOUS_STRUCT
#define DUMMYSTRUCTNAME
#define DUMMYSTRUCTNAME2
#define DUMMYSTRUCTNAME3
#define DUMMYSTRUCTNAME4
#define DUMMYSTRUCTNAME5
#define DUMMYUNIONNAME
#define DUMMYUNIONNAME2
#define ANYSIZE_ARRAY 1

#define C_ASSERT(expr) extern char (*c_assert(void)) [(expr) ? 1 : -1]

/*
 * Returns the byte offset of a field in a structure of the given type.
 */
#define FIELD_OFFSET(t,f)	((LONG)__builtin_offsetof(t,f))

#undef CONST
#define CONST const
#define VOID void
typedef void *PVOID, *LPVOID, **PPVOID;
typedef CONST VOID *PCVOID, *LPCVOID;

typedef char CHAR, CCHAR;
typedef unsigned char UCHAR;
typedef signed char SCHAR;
typedef CHAR *PCHAR, *PCCHAR, *PSTR, *LPSTR;
typedef UCHAR *PUCHAR;
typedef CONST CHAR *PCSTR, *LPCSTR, *PCSZ;
typedef unsigned char BYTE, *PBYTE, *LPBYTE;
typedef CHAR *LPCH, *PCH, *PNZCH, *PSZ;
typedef CONST CHAR *LPCCH, *PCCH, *PCNZCH;

typedef int8_t INT8;
typedef uint8_t UINT8, *PUINT8;

typedef wchar_t WCHAR;
typedef WCHAR *PWCHAR, *PWCH, *LPWCH, *PWSTR, *LPWSTR;
typedef CONST WCHAR *PCWCH, *LPCWCH, *PCWSTR, *LPCWSTR;

typedef _NullNull_terminated_ WCHAR *PZZWSTR;
typedef _NullNull_terminated_ CONST WCHAR *PCZZWSTR;

// This differs from Windows (Windows defines BOOLEAN as UCHAR)
typedef _Bool BOOLEAN, BOOL, *PBOOL, *LPBOOL, *PBOOLEAN;
#define TRUE (1)
#define FALSE (0)

typedef short SHORT, CSHORT;
typedef unsigned short USHORT;
typedef SHORT *PSHORT;
typedef USHORT *PUSHORT;
typedef unsigned short WORD, *LPWORD;
typedef USHORT LANGID;

typedef int16_t INT16;
typedef uint16_t UINT16, *PUINT16;

typedef int INT, *LPINT;
typedef unsigned int UINT, *LPUINT;

typedef int32_t LONG, *PLONG, *LPLONG;
typedef uint32_t ULONG, *PULONG, CLONG, *PCLONG, UINT32, *PUINT32, DWORD, *PDWORD, *LPDWORD;

typedef uint64_t ULONGLONG, *PULONGLONG, DWORDLONG, *PDWORDLONG;
typedef int64_t LONGLONG, *PLONGLONG;

typedef uintptr_t ULONG_PTR, SIZE_T, *PSIZE_T, *PULONG_PTR,
    DWORD_PTR, *PDWORD_PTR, UINT_PTR, *PUINT_PTR;
typedef intptr_t LONG_PTR, SSIZE_T, *PSSIZE_T, *PLONG_PTR, INT_PTR, *PINT_PTR;

typedef int64_t LONG64, *PLONG64;
typedef int64_t INT64,  *PINT64;
typedef uint64_t ULONG64, *PULONG64;
typedef uint64_t DWORD64, *PDWORD64;
typedef uint64_t UINT64,  *PUINT64;

#define BYTE_MAX INT8_MAX
#define SHORT_MAX INT16_MAX
#define USHORT_MAX UINT16_MAX
#define WORD_MAX USHORT_MAX
#define DWORD_MAX ULONG_MAX
#define LONGLONG_MAX INT64_MAX
#define LONG64_MAX INT64_MAX
#define ULONGLONG_MAX UINT64_MAX
#define DWORDLONG_MAX UINT64_MAX
#define ULONG64_MAX UINT64_MAX
#define DWORD64_MAX UINT64_MAX
#define INT_PTR_MAX INTPTR_MAX
#define UINT_PTR_MAX UINTPTR_MAX
#define LONG_PTR_MAX INTPTR_MAX
#define ULONG_PTR_MAX UINTPTR_MAX
#define DWORD_PTR_MAX ULONG_PTR_MAX
#define PTRDIFF_T_MAX PTRDIFF_MAX
#define SIZE_T_MAX UINTPTR_MAX
#define SSIZE_T_MAX INTPTR_MAX
#define _SIZE_T_MAX SIZE_T_MAX

#define BYTE_MIN INT8_MIN
#define SHORT_MIN INT16_MIN
#define USHORT_MIN UINT16_MIN
#define WORD_MIN USHORT_MIN
#define DWORD_MIN ULONG_MIN
#define LONGLONG_MIN INT64_MIN
#define LONG64_MIN INT64_MIN
#define ULONGLONG_MIN UINT64_MIN
#define DWORDLONG_MIN UINT64_MIN
#define ULONG64_MIN UINT64_MIN
#define DWORD64_MIN UINT64_MIN
#define INT_PTR_MIN INTPTR_MIN
#define UINT_PTR_MIN UINTPTR_MIN
#define LONG_PTR_MIN INTPTR_MIN
#define ULONG_PTR_MIN UINTPTR_MIN
#define DWORD_PTR_MIN ULONG_PTR_MIN
#define PTRDIFF_T_MIN PTRDIFF_MIN
#define SIZE_T_MIN UINTPTR_MIN
#define SSIZE_T_MIN INTPTR_MIN
#define _SIZE_T_MIN SIZE_T_MIN

#define MAXBYTE   0xff
#define MAXWORD   0xffff
#define MAXDWORD  0xffffffff

#define MAXUCHAR	(0xFF)
#define MAXUSHORT	USHORT_MAX
#define MAXSHORT        (0X7FFF)
#define MAXULONG	ULONG_MAX
#define MAXULONGLONG	ULONG64_MAX
#define MAXULONG_PTR	ULONG_PTR_MAX
#define MAXLONG_PTR	LONG_PTR_MAX
#define MAXLONG		LONG_MAX
#define MAXLONGLONG	LONGLONG_MAX

#define MINUSHORT	USHORT_MIN
#define MINULONG	ULONG_MIN
#define MINULONGLONG	ULONG64_MIN
#define MINULONG_PTR	ULONG_PTR_MIN
#define MINLONG_PTR	LONG_PTR_MIN
#define MINLONG		LONG_MIN
#define MINLONGLONG	LONGLONG_MIN

#if defined(_MSC_VER) && !defined(MIDL_PASS) && !defined(RC_INVOKED)
 #define POINTER_64 __ptr64
 #if defined(_WIN64)
  #define POINTER_32 __ptr32
 #else
  #define POINTER_32
 #endif
#else
 #define POINTER_64
 #define POINTER_32
#endif /* defined(_MSC_VER) && !defined(MIDL_PASS) && !defined(RC_INVOKED) */

typedef void * POINTER_64 PVOID64;
#define NULL64  ((void * POINTER_64)0)

typedef PVOID HANDLE, HMODULE, HINSTANCE;
#define DECLARE_HANDLE(name) typedef HANDLE name
typedef HANDLE *PHANDLE;
typedef LONG HRESULT;

#define HandleToUlong(h) ((ULONG)(ULONG_PTR)(h))
#define HandleToLong(h) ((LONG)(LONG_PTR)(h))
#define ULongToHandle(h) ((HANDLE)(ULONG_PTR) (h))
#define LongToHandle(h) ((HANDLE)(LONG_PTR) (h))
#define PtrToUlong(p) ((ULONG)(ULONG_PTR) (p))
#define PtrToLong(p) ((LONG)(LONG_PTR) (p))
#define PtrToUint(p) ((UINT)(UINT_PTR) (p))
#define PtrToInt(p) ((INT)(INT_PTR) (p))
#define PtrToUshort(p) ((USHORT)(ULONG_PTR)(p))
#define PtrToShort(p) ((SHORT)(LONG_PTR)(p))
#define IntToPtr(i)    ((VOID*)(INT_PTR)((INT)i))
#define UIntToPtr(ui)  ((VOID*)(UINT_PTR)((UINT)ui))
#define LongToPtr(l)   ((VOID*)(LONG_PTR)((LONG)l))
#define ULongToPtr(ul)  ((VOID*)(ULONG_PTR)((ULONG)ul))

#define HandleToULong(h) HandleToUlong(h)

#define UlongToHandle(ul) ULongToHandle(ul)
#define UlongToPtr(ul) ULongToPtr(ul)
#define UintToPtr(ui) UIntToPtr(ui)

typedef LONG NTSTATUS;
typedef NTSTATUS *PNTSTATUS;

#define STATUS_SEVERITY_SUCCESS         0x0
#define STATUS_SEVERITY_INFORMATIONAL   0x1
#define STATUS_SEVERITY_WARNING         0x2
#define STATUS_SEVERITY_ERROR           0x3
#define ERROR_SEVERITY_SUCCESS		0x00000000
#define ERROR_SEVERITY_INFORMATIONAL	0x40000000
#define ERROR_SEVERITY_WARNING		0x80000000
#define ERROR_SEVERITY_ERROR		0xC0000000

/* Status is success if and only if highest bit is zero */
#define NT_SUCCESS(Status)	(((NTSTATUS)(Status)) >= 0)
#define NT_INFORMATION(Status)  (((ULONG)(Status) >> 30) == STATUS_SEVERITY_INFORMATIONAL)
#define NT_WARNING(Status)	(((ULONG)(Status) >> 30) == STATUS_SEVERITY_WARNING)
#define NT_ERROR(Status)	(((ULONG)(Status) >> 30) == STATUS_SEVERITY_ERROR)

/*
 * Doubly-linked list and related list routines
 */
typedef struct _LIST_ENTRY {
    struct _LIST_ENTRY *Flink;
    struct _LIST_ENTRY *Blink;
} LIST_ENTRY, *PLIST_ENTRY;

/*
 * Large Integer Unions
 */
typedef union _LARGE_INTEGER {
    struct {
        ULONG LowPart;
        LONG HighPart;
    };
    LONGLONG QuadPart;
} LARGE_INTEGER, *PLARGE_INTEGER;

typedef union _ULARGE_INTEGER {
    struct {
        ULONG LowPart;
        ULONG HighPart;
    };
    ULONGLONG QuadPart;
} ULARGE_INTEGER, *PULARGE_INTEGER;

/* Locally Unique Identifier */
typedef struct _LUID {
    ULONG LowPart;
    LONG HighPart;
} LUID, *PLUID;
