#pragma once

#include <stdint.h>
#include <stddef.h>
#include <excpt.h>

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

#ifdef _M_IX86
#define FASTCALL __fastcall
#define NTAPI __stdcall
#else
#define FASTCALL
#define NTAPI
#endif

#define DECLSPEC_IMPORT __declspec(dllimport)
#define DECLSPEC_NORETURN   __declspec(noreturn)

/* FIXME: dllimport/dllexport */
#define NTSYSAPI
#define NTSYSCALLAPI

#undef CONST
#define CONST const
#define VOID void
typedef void *PVOID, **PPVOID;

typedef char CHAR;
typedef unsigned char UCHAR;
typedef signed char SCHAR;
typedef CHAR *PCHAR;
typedef UCHAR *PUCHAR;
typedef CONST CHAR *PCSTR;
typedef unsigned char BYTE;

typedef wchar_t WCHAR;
typedef WCHAR *PWCHAR, *PWSTR;
typedef CONST WCHAR *PCWCH, *PCWSTR;

typedef UCHAR BOOLEAN;
typedef BOOLEAN *PBOOLEAN;
#define TRUE (1)
#define FALSE (0)

typedef short SHORT;
typedef unsigned short USHORT;
typedef SHORT *PSHORT;
typedef USHORT *PUSHORT;

typedef int32_t LONG;
typedef uint32_t ULONG;
typedef LONG *PLONG;
typedef ULONG *PULONG;

typedef uint64_t ULONGLONG, *PULONGLONG;
typedef int64_t LONGLONG, *PLONGLONG;

typedef uintptr_t ULONG_PTR;
typedef intptr_t LONG_PTR;
typedef ULONG_PTR SIZE_T;

typedef int64_t LONG64, *PLONG64;
typedef int64_t INT64,  *PINT64;
typedef uint64_t ULONG64, *PULONG64;
typedef uint64_t DWORD64, *PDWORD64;
typedef uint64_t UINT64,  *PUINT64;

#define MAXUSHORT	(0xffff)
#define MAXULONG_PTR	(~((ULONG_PTR)0))
#define MAXLONG_PTR	((LONG_PTR)(MAXULONG_PTR >> 1))
#define MINLONG_PTR	(~MAXLONG_PTR)
#define MAXLONGLONG	(0x7fffffffffffffffLL)
#define MAXULONG	(0xffffffffUL)

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
#define _In_
#define _Out_
#define _Inout_

#define UNICODE_NULL ((WCHAR)0)

typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PCHAR Buffer;
} STRING, *PSTRING;

typedef struct _CSTRING
{
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
static inline
VOID InitializeListHead(IN PLIST_ENTRY ListHead)
{
    ListHead->Flink = ListHead->Blink = ListHead;
}

static inline
VOID InsertHeadList(IN PLIST_ENTRY ListHead,
		    IN PLIST_ENTRY Entry)
{
    PLIST_ENTRY OldFlink;
    OldFlink = ListHead->Flink;
    Entry->Flink = OldFlink;
    Entry->Blink = ListHead;
    OldFlink->Blink = Entry;
    ListHead->Flink = Entry;
}

static inline
VOID InsertTailList(IN PLIST_ENTRY ListHead,
		    IN PLIST_ENTRY Entry)
{
    PLIST_ENTRY OldBlink;
    OldBlink = ListHead->Blink;
    Entry->Flink = ListHead;
    Entry->Blink = OldBlink;
    OldBlink->Flink = Entry;
    ListHead->Blink = Entry;
}

static inline
BOOLEAN IsListEmpty(IN const LIST_ENTRY * ListHead)
{
    return (BOOLEAN)(ListHead->Flink == ListHead);
}

/* Returns TRUE if list is empty after removal */
static inline
BOOLEAN RemoveEntryList(IN PLIST_ENTRY Entry)
{
    PLIST_ENTRY OldFlink;
    PLIST_ENTRY OldBlink;

    OldFlink = Entry->Flink;
    OldBlink = Entry->Blink;
    OldFlink->Blink = OldBlink;
    OldBlink->Flink = OldFlink;
    return (BOOLEAN)(OldFlink == OldBlink);
}

static inline
PLIST_ENTRY RemoveHeadList(IN PLIST_ENTRY ListHead)
{
    PLIST_ENTRY Flink;
    PLIST_ENTRY Entry;

    Entry = ListHead->Flink;
    Flink = Entry->Flink;
    ListHead->Flink = Flink;
    Flink->Blink = ListHead;
    return Entry;
}

static inline
PLIST_ENTRY RemoveTailList(IN PLIST_ENTRY ListHead)
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

/*
 * Returns the byte offset of a field in a structure of the given type.
 */
#define FIELD_OFFSET(Type, Field)    ((LONG)(LONG_PTR)&(((Type *)0)->Field))

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
