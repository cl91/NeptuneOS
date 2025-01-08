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
#if defined(_WIN64)
    /* Make sure the header is 16 byte aligned */
    if (((ULONG_PTR) SListHead & 0xf) != 0) {
	DPRINT1("Unaligned SListHead: 0x%p\n", SListHead);
	RtlRaiseStatus(STATUS_DATATYPE_MISALIGNMENT);
    }

    /* Initialize the Region member */
#if defined(_IA64_)
    /* On Itanium we store the region in the list head */
    SListHead->Region = (ULONG_PTR) SListHead & VRN_MASK;
#else
    /* On amd64 we don't need to store anything */
    SListHead->Region = 0;
#endif				/* _IA64_ */
#endif				/* _WIN64 */

    SListHead->Alignment = 0;
}

NTAPI PSLIST_ENTRY RtlFirstEntrySList(IN const SLIST_HEADER *SListHead)
{
#if defined(_WIN64)
    /* Check if the header is initialized as 16 byte header */
    if (SListHead->Header16.HeaderType) {
	return (PVOID) (SListHead->Region & ~0xFLL);
    } else {
	union {
	    ULONG64 Region;
	    struct {
		ULONG64 Reserved:4;
		ULONG64 NextEntry:39;
		ULONG64 Reserved2:21;
	    } Bits;
	} Pointer;

#if defined(_IA64_)
	/* On Itanium we stored the region in the list head */
	Pointer.Region = SListHead->Region;
#else
	/* On amd64 we just use the list head itself */
	Pointer.Region = (ULONG64) SListHead;
#endif
	Pointer.Bits.NextEntry = SListHead->Header8.NextEntry;
	return (PVOID) Pointer.Region;
    }
#else
    return SListHead->Next.Next;
#endif
}

NTAPI USHORT RtlQueryDepthSList(IN PSLIST_HEADER SListHead)
{
#if defined(_WIN64)
    return (USHORT) (SListHead->Alignment & 0xffff);
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
