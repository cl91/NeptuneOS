/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS Runtime Library
 * PURPOSE:         Slist Routines
 * FILE:            lib/rtl/slist.c
 * PROGRAMERS:      Stefan Ginsberg (stefan.ginsberg@reactos.org)
 *                  Timo Kreuzer (timo.kreuzer@reactos.org)
 */

/* INCLUDES *****************************************************************/

#include <ntdll.h>

/* FUNCTIONS ***************************************************************/

NTAPI VOID RtlInitializeSListHead(OUT PSLIST_HEADER SListHead)
{
#ifdef _WIN64
    /* Make sure the header is 16 byte aligned */
    if (((ULONG_PTR)SListHead & 0xf) != 0) {
	DPRINT1("Unaligned SListHead: %p\n", SListHead);
	RtlRaiseStatus(STATUS_DATATYPE_MISALIGNMENT);
    }

    SListHead->Region = 0;
    /* We always use the 16-byte header on 64-bit architectures */
    SListHead->Header16.HeaderType = 1;
#endif				/* _WIN64 */

    SListHead->Alignment = 0;
}

NTAPI PSLIST_ENTRY RtlFirstEntrySList(IN const SLIST_HEADER *SListHead)
{
#ifdef _WIN64
    /* Make sure the header is initialized as 16 byte header */
    assert(SListHead->Header16.HeaderType);
    return (PSLIST_ENTRY)((ULONG_PTR)SListHead->Header16.NextEntry << 4);
#else
    return SListHead->Next.Next;
#endif
}

NTAPI USHORT RtlQueryDepthSList(IN PSLIST_HEADER SListHead)
{
#ifdef _WIN64
    return SListHead->Header16.Depth;
#else
    return SListHead->Depth;
#endif
}

FASTCALL PSLIST_ENTRY RtlInterlockedPushListSList(IN OUT PSLIST_HEADER SListHead,
						  IN OUT PSLIST_ENTRY List,
						  IN OUT PSLIST_ENTRY ListEnd,
						  IN ULONG Count)
{
#ifdef _WIN64
    SLIST_HEADER OldSListHead, NewSListHead;
    PSLIST_ENTRY FirstEntry;

    ASSERT(((ULONG_PTR)SListHead & 0xF) == 0);
    ASSERT(((ULONG_PTR)List & 0xF) == 0);

    BOOLEAN Exchanged;
    do {
	/* Capture the current SListHead */
	OldSListHead = *SListHead;

	/* Link the last list entry */
	FirstEntry = (PSLIST_ENTRY)(SListHead->Region & ~0xFLL);
	ListEnd->Next = FirstEntry;

	/* Set up new SListHead */
	NewSListHead = OldSListHead;
	NewSListHead.Header16.Depth += Count;
	NewSListHead.Header16.Sequence++;
	NewSListHead.Region = (ULONG64)List;
	NewSListHead.Header16.HeaderType = 1;
	NewSListHead.Header16.Init = 1;

	/* Atomically exchange the SlistHead with the new one */
	Exchanged = InterlockedCompareExchange128((PLONG64)SListHead,
						  NewSListHead.Region,
						  NewSListHead.Alignment,
						  (PLONG64)&OldSListHead);
    } while (!Exchanged);

    return FirstEntry;
#else
    SLIST_HEADER OldHeader, NewHeader;
    ULONGLONG Compare;

    /* Read the header */
    OldHeader = *SListHead;

    do {
	/* Link the last list entry */
	ListEnd->Next = OldHeader.Next.Next;

	/* Create a new header */
	NewHeader = OldHeader;
	NewHeader.Next.Next = List;
	NewHeader.Depth += Count;
	NewHeader.Sequence++;

	/* Try to exchange atomically */
	Compare = OldHeader.Alignment;
	OldHeader.Alignment = InterlockedCompareExchange64((PLONGLONG) &SListHead->Alignment,
							   NewHeader.Alignment,
							   Compare);
    } while (OldHeader.Alignment != Compare);

    /* Return the old first entry */
    return OldHeader.Next.Next;
#endif /* _WIN64 */
}

PSLIST_ENTRY RtlInterlockedFlushSList(PSLIST_HEADER SListHead)
{
    SLIST_HEADER OldList, NewList;

#ifdef _WIN64
    if (!SListHead->Header16.NextEntry) {
	return NULL;
    }
    NewList.Alignment = NewList.Region = 0;
    /* We always use the 16-byte header on WIN64 */
    NewList.Header16.HeaderType = 1;
    do {
        OldList = *SListHead;
        NewList.Header16.Sequence = OldList.Header16.Sequence + 1;
    } while (!InterlockedCompareExchange128((PLONG64)SListHead, NewList.Region,
					    NewList.Alignment, (PLONG64)&OldList));
    return (PSLIST_ENTRY)((ULONG_PTR)OldList.Header16.NextEntry << 4);
#else
    if (!SListHead->Next.Next) {
	return NULL;
    }
    NewList.Alignment = 0;
    do {
        OldList = *SListHead;
        NewList.Sequence = OldList.Sequence + 1;
    } while (InterlockedCompareExchange64((PLONG64)&SListHead->Alignment, NewList.Alignment,
                                          OldList.Alignment) != OldList.Alignment);
    return OldList.Next.Next;
#endif
}

PSLIST_ENTRY RtlInterlockedPushEntrySList(PSLIST_HEADER SListHead, PSLIST_ENTRY Entry)
{
    SLIST_HEADER OldList, NewList;

#ifdef _WIN64
    NewList.Header16.HeaderType = 1;
    NewList.Header16.NextEntry = (ULONG_PTR)Entry >> 4;
    do {
        OldList = *SListHead;
        Entry->Next = (PSLIST_ENTRY)((ULONG_PTR)OldList.Header16.NextEntry << 4);
        NewList.Header16.Depth = OldList.Header16.Depth + 1;
        NewList.Header16.Sequence = OldList.Header16.Sequence + 1;
    } while (!InterlockedCompareExchange128((PLONG64)SListHead, NewList.Region,
					    NewList.Alignment, (PLONG64)&OldList));
    return (PSLIST_ENTRY)((ULONG_PTR)OldList.Header16.NextEntry << 4);
#else
    NewList.Next.Next = Entry;
    do {
        OldList = *SListHead;
        Entry->Next = OldList.Next.Next;
        NewList.Depth = OldList.Depth + 1;
        NewList.Sequence = OldList.Sequence + 1;
    } while (InterlockedCompareExchange64((PLONG64)&SListHead->Alignment, NewList.Alignment,
                                          OldList.Alignment) != OldList.Alignment);
    return OldList.Next.Next;
#endif
}

PSLIST_ENTRY RtlInterlockedPopEntrySList(PSLIST_HEADER SListHead)
{
    SLIST_HEADER OldList, NewList;
    PSLIST_ENTRY Entry;

#ifdef _WIN64
    do {
        OldList = *SListHead;
	Entry = (PSLIST_ENTRY)((ULONG_PTR)OldList.Header16.NextEntry << 4);
        if (!Entry) {
	    return NULL;
	}
        /* Entry could be deleted by another thread */
	__try {
	    NewList.Header16.HeaderType = 1;
            NewList.Header16.NextEntry = (ULONG_PTR)Entry->Next >> 4;
            NewList.Header16.Depth = OldList.Header16.Depth - 1;
            NewList.Header16.Sequence = OldList.Header16.Sequence + 1;
        } __except(GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION) {
        }
    } while (!InterlockedCompareExchange128((PLONG64)SListHead, NewList.Region,
					    NewList.Alignment, (PLONG64)&OldList));
#else
    do {
        OldList = *SListHead;
	Entry = OldList.Next.Next;
        if (!Entry) {
	    return NULL;
	}
        /* Entry could be deleted by another thread */
        __try {
            NewList.Next.Next = Entry->Next;
            NewList.Depth = OldList.Depth - 1;
            NewList.Sequence = OldList.Sequence + 1;
        } __except(GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION) {
        }
    } while (InterlockedCompareExchange64((PLONG64)&SListHead->Alignment, NewList.Alignment,
                                          OldList.Alignment) != OldList.Alignment);
#endif
    return Entry;
}
