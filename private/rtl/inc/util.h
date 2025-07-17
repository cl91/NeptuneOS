#pragma once

#include <nt.h>
#include <debug.h>
#include <structures_gen.h>
#include <services.h>
#include <ctype.h>
#include <pool.h>

#define EX_POOL_SMALLEST_BLOCK	(RTL_POOL_SMALLEST_BLOCK)
#define EX_POOL_BLOCK_SHIFT	(RTL_POOL_BLOCK_SHIFT)

C_ASSERT(EX_POOL_SMALLEST_BLOCK == (1ULL << EX_POOL_BLOCK_SHIFT));

FORCEINLINE MWORD PsThreadIdToCSpaceGuard(IN ULONG_PTR ThreadId)
{
    assert(IS_ALIGNED_BY(ThreadId, EX_POOL_SMALLEST_BLOCK));
    return (ThreadId >> EX_POOL_BLOCK_SHIFT) <<
	(PROCESS_SHARED_CNODE_LOG2SIZE + THREAD_PRIVATE_CNODE_LOG2SIZE);
}

FORCEINLINE MWORD PsGetGuardValueOfCap(IN MWORD Cap)
{
    ULONG Bits = PROCESS_SHARED_CNODE_LOG2SIZE + THREAD_PRIVATE_CNODE_LOG2SIZE;
    return (Cap >> Bits) << Bits;
}

FORCEINLINE MWORD PsGetThreadCNodeIndexOfCap(IN MWORD Cap)
{
    return (Cap >> PROCESS_SHARED_CNODE_LOG2SIZE) &
	((1ULL << THREAD_PRIVATE_CNODE_LOG2SIZE) - 1);
}

FORCEINLINE BOOLEAN PsCapIsProcessShared(IN MWORD Cap)
{
    BOOLEAN Value = !PsGetThreadCNodeIndexOfCap(Cap) && !PsGetGuardValueOfCap(Cap);
    if (Value) {
	/* In this case the server should NOT have marked the cap with a guard value. */
	assert(!PsGetGuardValueOfCap(Cap));
    }
    return Value;
}

FORCEINLINE BOOLEAN PsCapIsThreadPrivate(IN MWORD Cap)
{
    return !!PsGetThreadCNodeIndexOfCap(Cap);
}

#ifndef _NTOSKRNL_
FORCEINLINE MWORD RtlGetThreadCSpaceGuard()
{
    PNT_TIB NtTib = NtCurrentTib();
    assert(NtTib->ClientId.UniqueProcess);
    assert(NtTib->ClientId.UniqueThread);
    return PsThreadIdToCSpaceGuard((ULONG_PTR)NtTib->ClientId.UniqueThread);
}

/* This routine must only be called for the caps in the process-wide shared CNode */
FORCEINLINE MWORD RtlGetGuardedCapInProcessCNode(IN MWORD Cap)
{
    assert(!PsGetThreadCNodeIndexOfCap(Cap));
    assert(!PsGetGuardValueOfCap(Cap));
    return Cap | RtlGetThreadCSpaceGuard();
}

FORCEINLINE BOOLEAN PsCapHasCorrectGuard(IN MWORD Cap)
{
    assert(NtCurrentTib()->ClientId.UniqueProcess);
    assert(NtCurrentTib()->ClientId.UniqueThread);
    return PsGetGuardValueOfCap(Cap) ==
	   PsThreadIdToCSpaceGuard((MWORD)NtCurrentTib()->ClientId.UniqueThread);
}
#endif

FORCEINLINE BOOLEAN IsPow2OrZero(ULONG64 n) { return !(n & (n-1)); }
FORCEINLINE BOOLEAN IsPow2(ULONG64 n) { return n && IsPow2OrZero(n); }

/*
 * Helper functions for MWORD array as bitmaps
 */
FORCEINLINE BOOLEAN GetBit(MWORD *Map, ULONG Bit)
{
    ULONG WordOffset = Bit / MWORD_BITS;
    ULONG BitOffset = Bit % MWORD_BITS;

    return (Map[WordOffset] & (1ULL << BitOffset)) != 0;
}

FORCEINLINE VOID SetBit(MWORD *Map, ULONG Bit)
{
    ULONG WordOffset = Bit / MWORD_BITS;
    ULONG BitOffset = Bit % MWORD_BITS;

    Map[WordOffset] |= (1ULL << BitOffset);
}

FORCEINLINE VOID ClearBit(MWORD *Map, ULONG Bit)
{
    ULONG WordOffset = Bit / MWORD_BITS;
    ULONG BitOffset = Bit % MWORD_BITS;

    Map[WordOffset] &= ~(1ULL << BitOffset);
}

FORCEINLINE LONG GetFirstZeroBit(MWORD *Map, ULONG MaxBit)
{
    for (ULONG i = 0; i < MaxBit; i++) {
	if (!GetBit(Map, i)) {
	    return i;
	}
    }
    return -1;
}

/*
 * Helper functions for ULONG64 as bitmaps
 */
#define GetBit64(Map, Bit)	(!!((Map) & (1ULL << (Bit))))
#define SetBit64(Map, Bit)	((Map) |= (1ULL << (Bit)))
#define ClearBit64(Map, Bit)	((Map) &= ~(1ULL << (Bit)))

/*
 * Compute the hash of the given string. Note that string
 * is converted into lower-case first and then have its
 * hash value computed. The case conversion only applies
 * to English letters (ASCII).
 */
FORCEINLINE ULONG RtlpHashString(PCSTR Str)
{
    ULONG Hash = 5381;
    ULONG Chr;

    while ((Chr = (UCHAR)*Str++) != '\0') {
	Chr = tolower(Chr);
        Hash = ((Hash << 5) + Hash) + Chr; /* Hash * 33 + Chr */
    }
    return Hash;
}

FORCEINLINE ULONG RtlpHashStringEx(IN PCSTR Str,
				   IN ULONG Length) /* Excluding trailing '\0' */
{
    ULONG Hash = 5381;

    for (ULONG i = 0; i < Length; i++) {
	ULONG Chr = Str[i];
	if (Chr == '\0') {
	    break;
	}
 	Chr = tolower(Chr);
        Hash = ((Hash << 5) + Hash) + Chr; /* Hash * 33 + Chr */
    }
    return Hash;
}

#if !defined(_NTOSKRNL_) && defined(_MSC_VER)
#include <nturtl.h>
FORCEINLINE NTSTATUS RtlpUtf8ToUnicodeString(IN PVOID Heap,
					     IN PCSTR String,
					     OUT PUNICODE_STRING UnicodeString)
{
    assert(String != NULL);
    assert(UnicodeString != NULL);
    SIZE_T Length = strlen(String);
    if (!Length) {
	UnicodeString->Buffer = NULL;
	UnicodeString->Length = UnicodeString->MaximumLength = 0;
	return STATUS_SUCCESS;
    }
    SIZE_T BufferSize = sizeof(WCHAR) * Length;
    PWCHAR Buffer = RtlAllocateHeap(Heap, 0, BufferSize);
    if (Buffer == NULL) {
        return STATUS_NO_MEMORY;
    }
    ULONG UnicodeStringLength = 0;
    NTSTATUS Status = RtlUTF8ToUnicodeN(Buffer, BufferSize, &UnicodeStringLength,
                                        String, Length);
    if (!NT_SUCCESS(Status)) {
        RtlFreeHeap(Heap, 0, Buffer);
        return STATUS_NO_MEMORY;
    }
    UnicodeString->Buffer = Buffer;
    UnicodeString->Length = UnicodeStringLength;
    UnicodeString->MaximumLength = BufferSize;
    return STATUS_SUCCESS;
}

/* Frees the buffer used in the UNICODE_STRING conversion above */
FORCEINLINE VOID RtlpFreeUnicodeString(IN PVOID Heap,
				       IN UNICODE_STRING String)
{
    RtlFreeHeap(Heap, 0, String.Buffer);
}
#endif

/*
 * Doubly-linked list helper routines
 */
FORCEINLINE VOID InvalidateListEntry(IN PLIST_ENTRY ListEntry)
{
    ListEntry->Flink = ListEntry->Blink = NULL;
}

/*
 * Append the list pointed to by ListToAppend to the tail of the
 * list pointed to by ListHead.
 *
 * Note that this is different from the function AppendTailList.
 * Here ListToAppend is the list head of the list to be appended.
 */
FORCEINLINE VOID AppendTailListHead(IN PLIST_ENTRY ListHead,
				    IN PLIST_ENTRY ListToAppend)
{
    ListHead->Blink->Flink = ListToAppend->Flink;
    ListToAppend->Flink->Blink = ListHead->Blink;
    ListHead->Blink = ListToAppend->Blink;
    ListToAppend->Blink->Flink = ListHead;
    InvalidateListEntry(ListToAppend);
}

FORCEINLINE SIZE_T GetListLength(IN PLIST_ENTRY ListEntry)
{
    SIZE_T Length = 0;
    for (PLIST_ENTRY Ptr = ListEntry->Flink; Ptr != ListEntry; Ptr = Ptr->Flink) {
	Length++;
    }
    return Length;
}

FORCEINLINE BOOLEAN ListHasEntry(IN PLIST_ENTRY List,
				 IN PLIST_ENTRY Entry)
{
    assert(List != NULL);
    assert(Entry != NULL);
    assert(List->Flink != NULL);
    for (PLIST_ENTRY p = List->Flink; p != List; p = p->Flink) {
	if (p == Entry) {
	    assert(p->Flink);
	    assert(p->Blink);
	    return TRUE;
	}
    }
    return FALSE;
}

#define GetPrevEntryList(List, Type, Field, ListHead)	\
    ((List)->Blink == (ListHead) ? NULL :		\
     CONTAINING_RECORD((List)->Blink, Type, Field))

#define GetNextEntryList(List, Type, Field, ListHead)	\
    ((List)->Flink == (ListHead) ? NULL :		\
     CONTAINING_RECORD((List)->Flink, Type, Field))

#define LoopOverList(Entry, ListHead, Type, Field)			\
    for (Type *Entry = CONTAINING_RECORD((ListHead)->Flink, Type, Field), \
	     *__LoopOverList_flink = CONTAINING_RECORD((Entry)->Field.Flink, Type, Field); \
	 &(Entry)->Field != (ListHead); Entry = __LoopOverList_flink,	\
	     __LoopOverList_flink = CONTAINING_RECORD((__LoopOverList_flink)->Field.Flink, Type, Field))

#define ReverseLoopOverList(Entry, ListHead, Type, Field)		\
    for (Type *Entry = CONTAINING_RECORD((ListHead)->Blink, Type, Field), \
	     *__ReverseLoop_blink = CONTAINING_RECORD((Entry)->Field.Blink, Type, Field); \
	 &(Entry)->Field != (ListHead); Entry = __ReverseLoop_blink,	\
	     __ReverseLoop_blink = CONTAINING_RECORD((__ReverseLoop_blink)->Field.Blink, Type, Field))

FORCEINLINE PLIST_ENTRY GetNthEntryList(IN PLIST_ENTRY ListHead,
					IN ULONG Index)
{
    assert(ListHead != NULL);
    PLIST_ENTRY Entry = ListHead->Flink;
    for (ULONG i = 0; i < Index; i++) {
	assert(Entry != NULL);
	if (Entry == NULL || Entry == ListHead) {
	    return NULL;
	}
	Entry = Entry->Flink;
    }
    return Entry;
}

/* This uses a GCC extension (statement expressions). */
#define GetIndexedElementOfList(ListHead, Index, Type, Field)		\
    ({									\
	PLIST_ENTRY Entry = GetNthEntryList(ListHead, Index);           \
	(Entry == NULL) ? NULL : CONTAINING_RECORD(Entry, Type, Field); \
    })


PCSTR RtlDbgCapTypeToStr(cap_tag_t Type);

#if defined(CONFIG_DEBUG_BUILD) || defined(DEBUG) || defined(DBG) || defined(_DEBUG)
VOID KeDbgDumpIPCError(IN int Error);
#else
#define KeDbgDumpIPCError(x)
#endif	/* DEBUG */

#if defined(_NTOSKRNL_) || defined(_NTDLL_) || defined(_NTPSX_)
extern PCSTR RtlpDbgTraceModuleName;
#else
extern DECLSPEC_IMPORT PCSTR RtlpDbgTraceModuleName;
#endif

#define DbgTrace(...) { DbgPrint("%s %s(%d):  ", RtlpDbgTraceModuleName, __func__, __LINE__); DbgPrint(__VA_ARGS__); }

FORCEINLINE VOID RtlDbgPrintIndentation(IN LONG Indentation)
{
    for (LONG i = 0; i < Indentation; i++) {
	DbgPrint(" ");
    }
}

/*
 * This will generate a compile-time error if the function is marked
 * as async.
 */
typedef char __ASYNC_RETURN_CHECK_HELPER;
#define COMPILE_CHECK_ASYNC_RETURN					\
    { compile_assert(ERROR_YOU_MUST_USE_ASYNC_RETURN,			\
		     sizeof(__ASYNC_RETURN_CHECK_HELPER) == 1); }

/*
 * This macro shall not be used inside an async function. Use
 * ASYNC_RET_ERR_EX instead
 */
#define RET_ERR_EX(Expr, OnError)					\
    COMPILE_CHECK_ASYNC_RETURN;						\
    {NTSTATUS Status = (Expr); if (!NT_SUCCESS(Status)) {		\
	    DbgTrace("Expression %s in function %s @ %s:%d returned"	\
		     " error 0x%x\n",					\
		     #Expr, __func__, __FILE__, __LINE__, Status);	\
	    {OnError;} return Status; }}
/*
 * This macro shall not be used inside an async function. Use
 * ASYNC_RET_ERR instead
 */
#define RET_ERR(Expr)	RET_ERR_EX(Expr, {})

#define IF_ERR_GOTO(Label, Status, Expr)				\
    Status = (Expr);							\
    if (!NT_SUCCESS(Status)) {						\
	DbgTrace("Expression %s in function %s @ %s:%d returned"	\
		 " error 0x%x\n",					\
		 #Expr, __func__, __FILE__, __LINE__, Status);		\
	goto Label;							\
    }
