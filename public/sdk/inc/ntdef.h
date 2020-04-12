#pragma once

#include <stdint.h>
#include <stddef.h>

#ifdef __i386__
#define _M_IX86
#endif

#ifdef __x86_64
#define _M_AMD64
#endif

#ifdef _M_IX86
#define FASTCALL __fastcall
#else
#define FASTCALL
#endif

#define NTAPI __stdcall
#define DECLSPEC_IMPORT __declspec(dllimport)
#define DECLSPEC_NORETURN   __declspec(noreturn)

/* FIXME: dllimport/dllexport */
#define NTSYSAPI
#define NTSYSCALLAPI

#undef CONST
#define CONST const
#define VOID void
typedef void *PVOID;

typedef char CHAR;
typedef unsigned char UCHAR;
typedef signed char SCHAR;
typedef CHAR *PCHAR;
typedef UCHAR *PUCHAR;
typedef CONST CHAR *PCSTR;

typedef wchar_t WCHAR;
typedef WCHAR *PWCHAR, *PWSTR;

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

typedef uintptr_t ULONG_PTR;
typedef intptr_t LONG_PTR;

typedef PVOID HANDLE;
#define DECLARE_HANDLE(name) typedef HANDLE name
typedef HANDLE *PHANDLE;
typedef LONG HRESULT;

#define IN
#define OUT
#define OPTIONAL

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
