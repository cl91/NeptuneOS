#pragma once

#include <debug.h>
#include <nt.h>
#include <structures_gen.h>

static inline ULONG RtlpHashString(PCSTR Str)
{
    ULONG Hash = 5381;
    ULONG Chr;

    while ((Chr = (UCHAR) *Str++) != '\0') {
        Hash = ((Hash << 5) + Hash) + Chr; /* Hash * 33 + Chr */
    }
    return Hash;
}

#ifndef _NTOSKRNL_
#include <nturtl.h>
static inline NTSTATUS RtlpUtf8ToUnicodeString(IN PVOID Heap,
					       IN PCSTR String,
					       OUT PUNICODE_STRING UnicodeString)
{
    assert(String != NULL);
    assert(UnicodeString != NULL);
    SIZE_T Length = strlen(String);
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
static inline VOID RtlpFreeUnicodeString(IN PVOID Heap,
					 IN UNICODE_STRING String)
{
    RtlFreeHeap(Heap, 0, String.Buffer);
}
#endif

/*
 * Doubly-linked list helper routines
 */
static inline VOID InvalidateListEntry(IN PLIST_ENTRY ListEntry)
{
    ListEntry->Flink = ListEntry->Blink = NULL;
}

static inline ULONG GetListLength(IN PLIST_ENTRY ListEntry)
{
    ULONG Length = 0;
    for (PLIST_ENTRY Ptr = ListEntry->Flink; Ptr != ListEntry; Ptr = Ptr->Flink) {
	Length++;
    }
    return Length;
}

#define LoopOverList(Entry, ListHead, Type, Field)			\
    for (Type *Entry = CONTAINING_RECORD((ListHead)->Flink, Type, Field), \
	     *__LoopOverList_flink = CONTAINING_RECORD((Entry)->Field.Flink, Type, Field); \
	 &(Entry)->Field != (ListHead); Entry = __LoopOverList_flink,	\
	     __LoopOverList_flink = CONTAINING_RECORD((__LoopOverList_flink)->Field.Flink, Type, Field))

#define ReverseLoopOverList(Entry, ListHead, Type, Field)		\
    for (Type *Entry = CONTAINING_RECORD((ListHead)->Blink, Type, Field), \
	     *__ReverseLoop_blink = CONTAINING_RECORD((Entry)->Field.Blink, Type, Field); \
	 &(Entry)->Field != (ListHead); Entry = __ReverseLoop_blink,	\
	     __ReverseLoop_blink = __CONTAINING_RECORD((__ReverseLoop_blink)->Field.Blink, Type, Field))

PCSTR RtlDbgCapTypeToStr(cap_tag_t Type);
VOID KeDbgDumpIPCError(IN int Error);

#define DbgTrace(...) { DbgPrint("%s:  ", __func__); DbgPrint(__VA_ARGS__); }

#define RET_ERR_EX(Expr, OnError)					\
    {NTSTATUS Status = (Expr); if (!NT_SUCCESS(Status)) {		\
	    DbgPrint("Expression %s in function %s @ %s:%d returned"	\
		     " error 0x%x\n",					\
		     #Expr, __func__, __FILE__, __LINE__, Status);	\
	    {OnError;} return Status; }}
#define RET_ERR(Expr)	RET_ERR_EX(Expr, {})

#define IF_ERR_GOTO(Label, Status, Expr)				\
    Status = (Expr);							\
    if (!NT_SUCCESS(Status)) {						\
	DbgPrint("Expression %s in function %s @ %s:%d returned"	\
		 " error 0x%x\n",					\
		 #Expr, __func__, __FILE__, __LINE__, Status);		\
	goto Label;							\
    }
