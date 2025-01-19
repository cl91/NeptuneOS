#pragma once

#ifdef __i386__
#ifndef _M_IX86
#define _M_IX86
#endif
#endif

#ifdef __x86_64
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
#include <stddef.h>
#include <excpt.h>
#include <limits.h>

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

#if defined(_M_IX86) || defined(_M_AMD64)
#define SYSTEM_CACHE_ALIGNMENT_SIZE 64
#else
#define SYSTEM_CACHE_ALIGNMENT_SIZE 128
#endif

#if defined(_M_IX86) || defined(_M_AMD64)
#define DECLSPEC_NOFPU		__attribute__((target("general-regs-only")))
#elif defined(_M_ARM64)
#define DECLSPEC_NOFPU		__attribute__((target("nofp")))
#else
#error "Unsupported architecture"
#endif

#define DECLSPEC_CACHEALIGN DECLSPEC_ALIGN(SYSTEM_CACHE_ALIGNMENT_SIZE)

#define DEPRECATED_BY(msg, repl)	__attribute__((deprecated(msg " Use " #repl ".", #repl)))

#if !defined(_NTSYSTEM_) && !defined(_NTOSKRNL_)
#define NTSYSAPI	DECLSPEC_IMPORT
#define NTSYSCALLAPI	DECLSPEC_IMPORT
#else
#define NTSYSAPI
#define NTSYSCALLAPI
#endif

#undef CONST
#define CONST const
#define VOID void
typedef void *PVOID, *LPVOID, **PPVOID;
typedef CONST VOID *PCVOID;

typedef char CHAR, CCHAR;
typedef unsigned char UCHAR;
typedef signed char SCHAR;
typedef CHAR *PCHAR;
typedef UCHAR *PUCHAR;
typedef CONST CHAR *PCSTR, *LPCSTR, *PCSZ;
typedef unsigned char BYTE, *PBYTE;
typedef CHAR *LPCH, *PCH, *PNZCH, *PSZ;
typedef CONST CHAR *LPCCH, *PCCH, *PCNZCH;

typedef int8_t INT8;
typedef uint8_t UINT8;

typedef wchar_t WCHAR;
typedef WCHAR *PWCHAR, *PWCH, *PWSTR, *LPWSTR;
typedef CONST WCHAR *PCWCH, *PCWSTR, *LPCWSTR;

// This differs from Windows (Windows defines BOOLEAN as UCHAR)
typedef _Bool BOOLEAN, BOOL;
typedef BOOLEAN *PBOOLEAN;
#define TRUE (1)
#define FALSE (0)

typedef short SHORT, CSHORT;
typedef unsigned short USHORT;
typedef SHORT *PSHORT;
typedef USHORT *PUSHORT;
typedef unsigned short WORD;

typedef int16_t INT16;
typedef uint16_t UINT16;

typedef int INT;
typedef unsigned int UINT;

typedef int32_t LONG;
typedef uint32_t ULONG, DWORD;
typedef LONG *PLONG;
typedef ULONG *PULONG, CLONG, *PCLONG, *LPDWORD;

typedef uint64_t ULONGLONG, *PULONGLONG;
typedef int64_t LONGLONG, *PLONGLONG;

typedef uintptr_t ULONG_PTR, SIZE_T, *PSIZE_T, *PULONG_PTR, DWORD_PTR, UINT_PTR, *PUINT_PTR;
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

#define MAXUSHORT	USHORT_MAX
#define MAXULONG	ULONG_MAX
#define MAXULONG_PTR	ULONG_PTR_MAX
#define MAXLONG_PTR	LONG_PTR_MAX
#define MAXLONG		LONG_MAX
#define MAXLONGLONG	LONGLONG_MAX

#define MINUSHORT	USHORT_MIN
#define MINULONG	ULONG_MIN
#define MINULONG_PTR	ULONG_PTR_MIN
#define MINLONG_PTR	LONG_PTR_MIN
#define MINLONG		LONG_MIN
#define MINLONGLONG	LONGLONG_MIN

typedef PVOID HANDLE, HMODULE, HINSTANCE;
#define DECLARE_HANDLE(name) typedef HANDLE name
typedef HANDLE *PHANDLE;
typedef LONG HRESULT;

typedef union _LARGE_INTEGER {
    struct {
        ULONG LowPart;
        LONG HighPart;
    };
    struct {
        ULONG LowPart;
        LONG HighPart;
    } u;
    LONGLONG QuadPart;
} LARGE_INTEGER, *PLARGE_INTEGER;

typedef union _ULARGE_INTEGER {
    struct {
        ULONG LowPart;
        ULONG HighPart;
    };
    struct {
        ULONG LowPart;
        ULONG HighPart;
    } u;
    ULONGLONG QuadPart;
} ULARGE_INTEGER, *PULARGE_INTEGER;

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
#define ANYSIZE_ARRAY

#define min(a, b) (((a) < (b)) ? (a) : (b))
#define max(a, b) (((a) > (b)) ? (a) : (b))

#define UNREFERENCED_PARAMETER(P) ((void)(P))
#define C_ASSERT(expr) extern char (*c_assert(void)) [(expr) ? 1 : -1]

#define UNICODE_NULL ((WCHAR)0)
#define UNICODE_STRING_MAX_BYTES ((USHORT) 65534)
#define UNICODE_STRING_MAX_CHARS (32767)
#define ANSI_NULL ((CHAR)0)

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _STRING {
    USHORT Length;
    USHORT MaximumLength;
    PCHAR Buffer;
} STRING, *PSTRING;

typedef struct _CSTRING {
    USHORT Length;
    USHORT MaximumLength;
    CONST CHAR *Buffer;
} CSTRING, *PCSTRING;

typedef const UNICODE_STRING* PCUNICODE_STRING;
typedef STRING ANSI_STRING;
typedef PSTRING PANSI_STRING;
typedef STRING OEM_STRING;
typedef PSTRING POEM_STRING;
typedef CONST STRING* PCOEM_STRING;
typedef STRING CANSI_STRING;
typedef PSTRING PCANSI_STRING;

struct _CONTEXT;
struct _EXCEPTION_RECORD;

typedef EXCEPTION_DISPOSITION
(*PEXCEPTION_ROUTINE) (IN struct _EXCEPTION_RECORD *ExceptionRecord,
		       IN PVOID EstablisherFrame,
		       IN OUT struct _CONTEXT *ContextRecord,
		       IN OUT PVOID DispatcherContext);

/*
 * Doubly-linked list and related list routines
 */
typedef struct _LIST_ENTRY
{
    struct _LIST_ENTRY *Flink;
    struct _LIST_ENTRY *Blink;
} LIST_ENTRY, *PLIST_ENTRY;

/* Returns the base address of a structure from a structure member */
#define CONTAINING_RECORD(address, type, field)				\
    ((type *)(((ULONG_PTR)address) - (ULONG_PTR)(&(((type *)0)->field))))

/* List Functions */
FORCEINLINE VOID InitializeListHead(IN PLIST_ENTRY ListHead)
{
    ListHead->Flink = ListHead;
    ListHead->Blink = ListHead;
}

FORCEINLINE VOID InsertHeadList(IN PLIST_ENTRY ListHead,
				IN PLIST_ENTRY Entry)
{
    PLIST_ENTRY OldFlink;
    OldFlink = ListHead->Flink;
    Entry->Flink = OldFlink;
    Entry->Blink = ListHead;
    OldFlink->Blink = Entry;
    ListHead->Flink = Entry;
}

FORCEINLINE VOID InsertTailList(IN PLIST_ENTRY ListHead,
				IN PLIST_ENTRY Entry)
{
    PLIST_ENTRY OldBlink;
    OldBlink = ListHead->Blink;
    Entry->Flink = ListHead;
    Entry->Blink = OldBlink;
    OldBlink->Flink = Entry;
    ListHead->Blink = Entry;
}

/*
 * Append the ListToAppend to the tail of the list pointed to by ListHead.
 * Note that ListToAppend does not have a list head.
 */
FORCEINLINE VOID AppendTailList(IN OUT PLIST_ENTRY ListHead,
				IN OUT PLIST_ENTRY ListToAppend)
{
  PLIST_ENTRY ListEnd = ListHead->Blink;
  ListHead->Blink->Flink = ListToAppend;
  ListHead->Blink = ListToAppend->Blink;
  ListToAppend->Blink->Flink = ListHead;
  ListToAppend->Blink = ListEnd;
}

FORCEINLINE BOOLEAN IsListEmpty(IN const LIST_ENTRY *ListHead)
{
    return (BOOLEAN)(ListHead->Flink == ListHead);
}

/* Returns TRUE if list is empty after removal */
FORCEINLINE BOOLEAN RemoveEntryList(IN PLIST_ENTRY Entry)
{
    PLIST_ENTRY OldFlink;
    PLIST_ENTRY OldBlink;

    OldFlink = Entry->Flink;
    OldBlink = Entry->Blink;
    OldFlink->Blink = OldBlink;
    OldBlink->Flink = OldFlink;
    return (BOOLEAN)(OldFlink == OldBlink);
}

FORCEINLINE PLIST_ENTRY RemoveHeadList(IN PLIST_ENTRY ListHead)
{
    PLIST_ENTRY Flink;
    PLIST_ENTRY Entry;

    Entry = ListHead->Flink;
    Flink = Entry->Flink;
    ListHead->Flink = Flink;
    Flink->Blink = ListHead;
    return Entry;
}

FORCEINLINE PLIST_ENTRY RemoveTailList(IN PLIST_ENTRY ListHead)
{
    PLIST_ENTRY Blink;
    PLIST_ENTRY Entry;

    Entry = ListHead->Blink;
    Blink = Entry->Blink;
    ListHead->Blink = Blink;
    Blink->Flink = ListHead;
    return Entry;
}

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _OBJECT_ATTRIBUTES_ANSI {
    ULONG Length;
    HANDLE RootDirectory;
    PCSTR ObjectName;	// UTF-8 encoded, NUL-terminated
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES_ANSI, *POBJECT_ATTRIBUTES_ANSI;

/*
 * Returns the byte offset of a field in a structure of the given type.
 */
#define FIELD_OFFSET(t,f)	((LONG)__builtin_offsetof(t,f))

/*
 * Returns the size of a field in a structure of the given type.
 */
#define RTL_FIELD_SIZE(Type, Field) (sizeof(((Type *)0)->Field))

/*
 * Returns the size of a structure of given type up through and including the given field.
 */
#define RTL_SIZEOF_THROUGH_FIELD(Type, Field)			\
    (FIELD_OFFSET(Type, Field) + RTL_FIELD_SIZE(Type, Field))

/*
 * Returns TRUE if the Field offset of a given Struct does not exceed Size
 */
#define RTL_CONTAINS_FIELD(Struct, Size, Field)				\
    ((((PCHAR)(&(Struct)->Field)) + sizeof((Struct)->Field)) <= (((PCHAR)(Struct))+(Size)))

/*
 * Additional Helper Macros
 */
#define RTL_FIELD_TYPE(type, field)	(((type*)0)->field)
#define RTL_BITS_OF(sizeOfArg)		(sizeof(sizeOfArg) * 8)
#define RTL_BITS_OF_FIELD(type, field)	(RTL_BITS_OF(RTL_FIELD_TYPE(type, field)))

#ifdef __GNUC__
#define RTL_NUMBER_OF(A)						\
    (({ int _check_array_type[__builtin_types_compatible_p(typeof(A),	\
		    typeof(&A[0])) ? -1 : 1];				\
	    (void)_check_array_type; }),				\
	(sizeof(A)/sizeof((A)[0])))
#elif defined(__cplusplus)
extern "C++" {
    template <typename T, size_t N>
	static char (& SAFE_RTL_NUMBER_OF(T (&)[N]))[N];
}
#define RTL_NUMBER_OF(A)	sizeof(SAFE_RTL_NUMBER_OF(A))
#else
#define RTL_NUMBER_OF(A)	(sizeof(A)/sizeof((A)[0]))
#endif

#define ARRAYSIZE(A)		RTL_NUMBER_OF(A)
#define _ARRAYSIZE(A)		RTL_NUMBER_OF(A)

#define RTL_NUMBER_OF_FIELD(type, field)		\
    (RTL_NUMBER_OF(RTL_FIELD_TYPE(type, field)))

/*
 * Alignment macros
 */
#define ALIGN_DOWN_BY(addr, align)			\
    ((ULONG_PTR)(addr) & ~((ULONG_PTR)(align) - 1))

#define ALIGN_UP_BY(addr, align)				\
    (ALIGN_DOWN_BY(((ULONG_PTR)(addr) + (align) - 1), (align)))

#define ALIGN_DOWN_POINTER_BY(ptr, align)	((PVOID)ALIGN_DOWN_BY((ptr), (align)))
#define ALIGN_UP_POINTER_BY(ptr, align)		((PVOID)ALIGN_UP_BY((ptr), (align)))
#define ALIGN_DOWN(addr, type)			ALIGN_DOWN_BY((addr), sizeof(type))
#define ALIGN_UP(addr, type)			ALIGN_UP_BY((addr), sizeof(type))
#define ALIGN_DOWN_POINTER(ptr, type)		ALIGN_DOWN_POINTER_BY((ptr), sizeof(type))
#define ALIGN_UP_POINTER(ptr, type)		ALIGN_UP_POINTER_BY((ptr), sizeof(type))

/* ULONG
 * BYTE_OFFSET(
 *     _In_ PVOID Va)
 */
#define BYTE_OFFSET(Va)					\
  ((ULONG) ((ULONG_PTR)(Va) & (PAGE_SIZE - 1)))

/* ULONG
 * BYTES_TO_PAGES(
 *     _In_ ULONG Size)
 *
 * Note: This needs to be like this to avoid overflows!
 */
#define BYTES_TO_PAGES(Size)						\
    (((Size) >> PAGE_SHIFT) + (((Size) & (PAGE_SIZE - 1)) != 0))

/* ULONG_PTR
 * ROUND_TO_PAGES(
 *     _In_ ULONG_PTR Size)
 */
#define ROUND_TO_PAGES(Size)					\
    (((ULONG_PTR) (Size) + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1))

/* ULONG
 * ADDRESS_AND_SIZE_TO_SPAN_PAGES(
 *     _In_ PVOID Va,
 *     _In_ ULONG Size)
 */
#define ADDRESS_AND_SIZE_TO_SPAN_PAGES(_Va, _Size)		\
    ((ULONG) ((((ULONG_PTR) (_Va) & (PAGE_SIZE - 1))		\
	       + (_Size) + (PAGE_SIZE - 1)) >> PAGE_SHIFT))

#define COMPUTE_PAGES_SPANNED(Va, Size)		\
    ADDRESS_AND_SIZE_TO_SPAN_PAGES(Va,Size)


#if defined(_WIN64)
#define POINTER_ALIGNMENT DECLSPEC_ALIGN(8)
#else
#define POINTER_ALIGNMENT
#endif

#if defined(_WIN64) || defined(_M_ALPHA)
#define MAX_NATURAL_ALIGNMENT sizeof(ULONGLONG)
#define MEMORY_ALLOCATION_ALIGNMENT 16
#else
#define MAX_NATURAL_ALIGNMENT sizeof(ULONG)
#define MEMORY_ALLOCATION_ALIGNMENT 8
#endif

/*
 * Use intrinsics for 32-bit and 64-bit multiplications on i386
 */
#ifdef _M_IX86
#define Int32x32To64(a,b) __emul(a,b)
#define UInt32x32To64(a,b) __emulu(a,b)
#else
#define Int32x32To64(a,b) (((__int64)(long)(a))*((__int64)(long)(b)))
#define UInt32x32To64(a,b)						\
    ((unsigned __int64)(unsigned int)(a) * (unsigned __int64)(unsigned int)(b))
#endif

#define Int64ShllMod32(a,b) ((unsigned __int64)(a)<<(b))
#define Int64ShraMod32(a,b) (((__int64)(a))>>(b))
#define Int64ShrlMod32(a,b) (((unsigned __int64)(a))>>(b))
