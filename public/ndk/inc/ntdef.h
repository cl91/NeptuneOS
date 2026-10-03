#pragma once

#include <ntbasedef.h>
#include <stddef.h>
#include <excpt.h>
#include <limits.h>

#if defined(_M_IX86) || defined(_M_AMD64)
#define DECLSPEC_NOFPU		__attribute__((target("general-regs-only")))
#elif defined(_M_ARM64)
#define DECLSPEC_NOFPU		__attribute__((target("nofp")))
#else
#error "Unsupported architecture"
#endif

#define DEPRECATED_BY(msg, repl)	__attribute__((deprecated(msg " Use " #repl ".", #repl)))

/* A LOCAL_HANDLE is an seL4 capability pointer in the current thread's CSpace */
typedef ULONG_PTR LOCAL_HANDLE, *PLOCAL_HANDLE;

/*
 * LUID helper routines
 */
FORCEINLINE BOOLEAN RtlEqualLuid(IN PLUID L1, IN PLUID L2) {
    return L1->HighPart == L2->HighPart && L1->LowPart  == L2->LowPart;
}

FORCEINLINE LUID RtlConvertUlongToLuid(IN ULONG Ulong)
{
    LUID TempLuid;

    TempLuid.LowPart = Ulong;
    TempLuid.HighPart = 0;
    return TempLuid;
}

#define min(a, b) (((a) < (b)) ? (a) : (b))
#define max(a, b) (((a) > (b)) ? (a) : (b))

#define SET_FLAG(Flags, Bit) ((Flags) |= (Bit))
#define CLEAR_FLAG(Flags, Bit) ((Flags) &= ~(Bit))
#define TEST_FLAG(Flags, Bit) (((Flags) & (Bit)) != 0)

#define UNREFERENCED_PARAMETER(P) ((void)(P))
#define ARGUMENT_PRESENT(ArgumentPointer)			\
    ((CHAR*)((ULONG_PTR)(ArgumentPointer)) != (CHAR*)NULL)

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

/* Returns TRUE if list is empty after removal. This routine zeros the
 * given LIST_ENTRY after its removal from the list. */
FORCEINLINE BOOLEAN RemoveEntryList(IN PLIST_ENTRY Entry)
{
    PLIST_ENTRY OldFlink;
    PLIST_ENTRY OldBlink;

    OldFlink = Entry->Flink;
    OldBlink = Entry->Blink;
    OldFlink->Blink = OldBlink;
    OldBlink->Flink = OldFlink;
    Entry->Flink = Entry->Blink = NULL;
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
    (({ int CheckArrayType[__builtin_types_compatible_p(typeof(A),	\
		    typeof(&A[0])) ? -1 : 1];				\
	    (void)CheckArrayType; }),					\
	(sizeof(A)/sizeof((A)[0])))
#elif defined(__cplusplus)
extern "C++" {
    template <typename T, size_t N>
    static char (&SAFE_RTL_NUMBER_OF(T (&)[N]))[N];
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


#define MEMORY_ALLOCATION_ALIGNMENT 16
#define MAX_NATURAL_ALIGNMENT sizeof(ULONG_PTR)
#define POINTER_ALIGNMENT DECLSPEC_ALIGN(MAX_NATURAL_ALIGNMENT)

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
