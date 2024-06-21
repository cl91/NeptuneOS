/*
 * COPYRIGHT:         See COPYING in the top level directory
 * PROJECT:           ReactOS system libraries
 * FILE:              lib/rtl/rangelist.c
 * PURPOSE:           Range list implementation
 * PROGRAMMERS:       No programmer listed.
 */

/* INCLUDES *****************************************************************/

#include "rtlp.h"

/* TYPES ********************************************************************/

typedef struct _RTL_RANGE_ENTRY {
    LIST_ENTRY Entry;
    RTL_RANGE Range;
} RTL_RANGE_ENTRY, *PRTL_RANGE_ENTRY;

/* FUNCTIONS ***************************************************************/

/**********************************************************************
 * NAME							EXPORTED
 * 	RtlAddRange
 *
 * DESCRIPTION
 *	Adds a range to a range list.
 *
 * ARGUMENTS
 *	RangeList		Range list.
 *	Start
 *	End
 *	Attributes
 *	Flags
 *	UserData
 *	Owner
 *
 * RETURN VALUE
 *	Status
 *
 * TODO:
 *   - Support shared ranges.
 *
 * @implemented
 */
NTAPI NTSTATUS RtlAddRange(IN OUT PRTL_RANGE_LIST RangeList, IN ULONGLONG Start,
			   IN ULONGLONG End, IN UCHAR Attributes, IN ULONG Flags,
			   IN PVOID UserData OPTIONAL, IN PVOID Owner OPTIONAL)
{
    PRTL_RANGE_ENTRY RangeEntry;
    //PRTL_RANGE_ENTRY Previous;
    PRTL_RANGE_ENTRY Current;
    PLIST_ENTRY Entry;

    if (Start > End)
	return STATUS_INVALID_PARAMETER;

    /* Create new range entry */
    RangeEntry = RtlpAllocateMemory(sizeof(RTL_RANGE_ENTRY), 'elRR');
    if (RangeEntry == NULL)
	return STATUS_INSUFFICIENT_RESOURCES;

    /* Initialize range entry */
    RangeEntry->Range.Start = Start;
    RangeEntry->Range.End = End;
    RangeEntry->Range.Attributes = Attributes;
    RangeEntry->Range.UserData = UserData;
    RangeEntry->Range.Owner = Owner;

    RangeEntry->Range.Flags = 0;
    if (Flags & RTL_RANGE_LIST_ADD_SHARED)
	RangeEntry->Range.Flags |= RTL_RANGE_SHARED;

    /* Insert range entry */
    if (RangeList->Count == 0) {
	InsertTailList(&RangeList->ListHead, &RangeEntry->Entry);
	RangeList->Count++;
	RangeList->Stamp++;
	return STATUS_SUCCESS;
    } else {
	//Previous = NULL;
	Entry = RangeList->ListHead.Flink;
	while (Entry != &RangeList->ListHead) {
	    Current = CONTAINING_RECORD(Entry, RTL_RANGE_ENTRY, Entry);
	    if (Current->Range.Start > RangeEntry->Range.End) {
		/* Insert before current */
		DPRINT("Insert before current\n");
		InsertTailList(&Current->Entry, &RangeEntry->Entry);

		RangeList->Count++;
		RangeList->Stamp++;
		return STATUS_SUCCESS;
	    }

	    //Previous = Current;
	    Entry = Entry->Flink;
	}

	DPRINT("Insert tail\n");
	InsertTailList(&RangeList->ListHead, &RangeEntry->Entry);
	RangeList->Count++;
	RangeList->Stamp++;
	return STATUS_SUCCESS;
    }

    RtlpFreeMemory(RangeEntry, 0);

    return STATUS_UNSUCCESSFUL;
}

/**********************************************************************
 * NAME							EXPORTED
 * 	RtlCopyRangeList
 *
 * DESCRIPTION
 *	Copy a range list.
 *
 * ARGUMENTS
 *	CopyRangeList	Pointer to the destination range list.
 *	RangeList	Pointer to the source range list.
 *
 * RETURN VALUE
 *	Status
 *
 * @implemented
 */
NTAPI NTSTATUS RtlCopyRangeList(OUT PRTL_RANGE_LIST CopyRangeList,
				IN PRTL_RANGE_LIST RangeList)
{
    PRTL_RANGE_ENTRY Current;
    PRTL_RANGE_ENTRY NewEntry;
    PLIST_ENTRY Entry;

    CopyRangeList->Flags = RangeList->Flags;

    Entry = RangeList->ListHead.Flink;
    while (Entry != &RangeList->ListHead) {
	Current = CONTAINING_RECORD(Entry, RTL_RANGE_ENTRY, Entry);

	NewEntry = RtlpAllocateMemory(sizeof(RTL_RANGE_ENTRY), 'elRR');
	if (NewEntry == NULL)
	    return STATUS_INSUFFICIENT_RESOURCES;

	RtlCopyMemory(&NewEntry->Range, &Current->Range, sizeof(RTL_RANGE));

	InsertTailList(&CopyRangeList->ListHead, &NewEntry->Entry);

	CopyRangeList->Count++;

	Entry = Entry->Flink;
    }

    CopyRangeList->Stamp++;

    return STATUS_SUCCESS;
}

/**********************************************************************
 * NAME							EXPORTED
 * 	RtlDeleteOwnersRanges
 *
 * DESCRIPTION
 *	Delete all ranges that belong to the given owner.
 *
 * ARGUMENTS
 *	RangeList	Pointer to the range list.
 *	Owner		User supplied value that identifies the owner
 *			of the ranges to be deleted.
 *
 * RETURN VALUE
 *	Status
 *
 * @implemented
 */
NTAPI NTSTATUS RtlDeleteOwnersRanges(IN OUT PRTL_RANGE_LIST RangeList, IN PVOID Owner)
{
    PRTL_RANGE_ENTRY Current;
    PLIST_ENTRY Entry;

    Entry = RangeList->ListHead.Flink;
    while (Entry != &RangeList->ListHead) {
	Current = CONTAINING_RECORD(Entry, RTL_RANGE_ENTRY, Entry);
	if (Current->Range.Owner == Owner) {
	    RemoveEntryList(Entry);
	    RtlpFreeMemory(Current, 0);

	    RangeList->Count--;
	    RangeList->Stamp++;
	}

	Entry = Entry->Flink;
    }

    return STATUS_SUCCESS;
}

/**********************************************************************
 * NAME							EXPORTED
 * 	RtlDeleteRange
 *
 * DESCRIPTION
 *	Deletes a given range.
 *
 * ARGUMENTS
 *	RangeList	Pointer to the range list.
 *	Start		Start of the range to be deleted.
 *	End		End of the range to be deleted.
 *	Owner		Owner of the ranges to be deleted.
 *
 * RETURN VALUE
 *	Status
 *
 * @implemented
 */
NTAPI NTSTATUS RtlDeleteRange(IN OUT PRTL_RANGE_LIST RangeList, IN ULONGLONG Start,
			      IN ULONGLONG End, IN PVOID Owner)
{
    PRTL_RANGE_ENTRY Current;
    PLIST_ENTRY Entry;

    Entry = RangeList->ListHead.Flink;
    while (Entry != &RangeList->ListHead) {
	Current = CONTAINING_RECORD(Entry, RTL_RANGE_ENTRY, Entry);
	if (Current->Range.Start == Start && Current->Range.End == End &&
	    Current->Range.Owner == Owner) {
	    RemoveEntryList(Entry);

	    RtlpFreeMemory(Current, 0);

	    RangeList->Count--;
	    RangeList->Stamp++;
	    return STATUS_SUCCESS;
	}

	Entry = Entry->Flink;
    }

    return STATUS_RANGE_NOT_FOUND;
}

/**********************************************************************
 * NAME							EXPORTED
 * 	RtlFindRange
 *
 * DESCRIPTION
 *	Searches for an unused range.
 *
 * ARGUMENTS
 *	RangeList		Pointer to the range list.
 *	Minimum
 *	Maximum
 *	Length
 *	Alignment
 *	Flags
 *	AttributeAvailableMask
 *	Context
 *	Callback
 *	Start
 *
 * RETURN VALUE
 *	Status
 *
 * TODO
 *	Support shared ranges and callback.
 *
 * @implemented
 */
NTAPI NTSTATUS RtlFindRange(IN PRTL_RANGE_LIST RangeList, IN ULONGLONG Minimum,
			    IN ULONGLONG Maximum, IN ULONG Length, IN ULONG Alignment,
			    IN ULONG Flags, IN UCHAR AttributeAvailableMask,
			    IN PVOID Context OPTIONAL,
			    IN PRTL_CONFLICT_RANGE_CALLBACK Callback OPTIONAL,
			    OUT PULONGLONG Start)
{
    PRTL_RANGE_ENTRY CurrentEntry;
    PRTL_RANGE_ENTRY NextEntry;
    PLIST_ENTRY Entry;
    ULONGLONG RangeMin;
    ULONGLONG RangeMax;

    if (Alignment == 0 || Length == 0) {
	return STATUS_INVALID_PARAMETER;
    }

    if (IsListEmpty(&RangeList->ListHead)) {
	*Start = ROUND_DOWN(Maximum - (Length - 1), Alignment);
	return STATUS_SUCCESS;
    }

    NextEntry = NULL;
    Entry = RangeList->ListHead.Blink;
    while (Entry != &RangeList->ListHead) {
	CurrentEntry = CONTAINING_RECORD(Entry, RTL_RANGE_ENTRY, Entry);

	RangeMax = NextEntry ? (NextEntry->Range.Start - 1) : Maximum;
	if (RangeMax + (Length - 1) < Minimum) {
	    return STATUS_RANGE_NOT_FOUND;
	}

	RangeMin = ROUND_DOWN(RangeMax - (Length - 1), Alignment);
	if (RangeMin < Minimum || (RangeMax - RangeMin) < (Length - 1)) {
	    return STATUS_RANGE_NOT_FOUND;
	}

	DPRINT("RangeMax: %I64x\n", RangeMax);
	DPRINT("RangeMin: %I64x\n", RangeMin);

	if (RangeMin > CurrentEntry->Range.End) {
	    *Start = RangeMin;
	    return STATUS_SUCCESS;
	}

	NextEntry = CurrentEntry;
	Entry = Entry->Blink;
    }

    RangeMax = NextEntry ? (NextEntry->Range.Start - 1) : Maximum;
    if (RangeMax + (Length - 1) < Minimum) {
	return STATUS_RANGE_NOT_FOUND;
    }

    RangeMin = ROUND_DOWN(RangeMax - (Length - 1), Alignment);
    if (RangeMin < Minimum || (RangeMax - RangeMin) < (Length - 1)) {
	return STATUS_RANGE_NOT_FOUND;
    }

    DPRINT("RangeMax: %I64x\n", RangeMax);
    DPRINT("RangeMin: %I64x\n", RangeMin);

    *Start = RangeMin;

    return STATUS_SUCCESS;
}

/**********************************************************************
 * NAME							EXPORTED
 * 	RtlFreeRangeList
 *
 * DESCRIPTION
 *	Deletes all ranges in a range list.
 *
 * ARGUMENTS
 *	RangeList	Pointer to the range list.
 *
 * RETURN VALUE
 *	None
 *
 * @implemented
 */
VOID NTAPI RtlFreeRangeList(IN PRTL_RANGE_LIST RangeList)
{
    PLIST_ENTRY Entry;
    PRTL_RANGE_ENTRY Current;

    while (!IsListEmpty(&RangeList->ListHead)) {
	Entry = RemoveHeadList(&RangeList->ListHead);
	Current = CONTAINING_RECORD(Entry, RTL_RANGE_ENTRY, Entry);

	DPRINT("Range start: %I64u\n", Current->Range.Start);
	DPRINT("Range end:   %I64u\n", Current->Range.End);

	RtlpFreeMemory(Current, 0);
    }

    RangeList->Flags = 0;
    RangeList->Count = 0;
}

/**********************************************************************
 * NAME							EXPORTED
 * 	RtlGetFirstRange
 *
 * DESCRIPTION
 *	Retrieves the first range of a range list.
 *
 * ARGUMENTS
 *	RangeList	Pointer to the range list.
 *	Iterator	Pointer to a user supplied list state buffer.
 *	Range		Pointer to the first range.
 *
 * RETURN VALUE
 *	Status
 *
 * @implemented
 */
NTAPI NTSTATUS RtlGetFirstRange(IN PRTL_RANGE_LIST RangeList,
				OUT PRTL_RANGE_LIST_ITERATOR Iterator,
				OUT PRTL_RANGE *Range)
{
    Iterator->RangeListHead = &RangeList->ListHead;
    Iterator->MergedHead = NULL;
    Iterator->Stamp = RangeList->Stamp;

    if (IsListEmpty(&RangeList->ListHead)) {
	Iterator->Current = NULL;
	*Range = NULL;
	return STATUS_NO_MORE_ENTRIES;
    }

    Iterator->Current = RangeList->ListHead.Flink;
    *Range = &((PRTL_RANGE_ENTRY)Iterator->Current)->Range;

    return STATUS_SUCCESS;
}

/**********************************************************************
 * NAME							EXPORTED
 * 	RtlGetNextRange
 *
 * DESCRIPTION
 *	Retrieves the next (or previous) range of a range list.
 *
 * ARGUMENTS
 *	Iterator	Pointer to a user supplied list state buffer.
 *	Range		Pointer to the first range.
 *	MoveForwards	TRUE, get next range
 *			FALSE, get previous range
 *
 * RETURN VALUE
 *	Status
 *
 * @implemented
 */
NTAPI NTSTATUS RtlGetNextRange(IN OUT PRTL_RANGE_LIST_ITERATOR Iterator,
			       OUT PRTL_RANGE *Range, IN BOOLEAN MoveForwards)
{
    PRTL_RANGE_LIST RangeList;
    PLIST_ENTRY Next;

    RangeList = CONTAINING_RECORD(Iterator->RangeListHead, RTL_RANGE_LIST, ListHead);
    if (Iterator->Stamp != RangeList->Stamp)
	return STATUS_INVALID_PARAMETER;

    if (Iterator->Current == NULL) {
	*Range = NULL;
	return STATUS_NO_MORE_ENTRIES;
    }

    if (MoveForwards) {
	Next = ((PRTL_RANGE_ENTRY)Iterator->Current)->Entry.Flink;
    } else {
	Next = ((PRTL_RANGE_ENTRY)Iterator->Current)->Entry.Blink;
    }

    if (Next == Iterator->RangeListHead) {
	Iterator->Current = NULL;
	*Range = NULL;
	return STATUS_NO_MORE_ENTRIES;
    }

    Iterator->Current = Next;
    *Range = &((PRTL_RANGE_ENTRY)Next)->Range;

    return STATUS_SUCCESS;
}

/**********************************************************************
 * NAME							EXPORTED
 * 	RtlInitializeRangeList
 *
 * DESCRIPTION
 *	Initializes a range list.
 *
 * ARGUMENTS
 *	RangeList	Pointer to a user supplied range list.
 *
 * RETURN VALUE
 *	None
 *
 * @implemented
 */
VOID NTAPI RtlInitializeRangeList(IN OUT PRTL_RANGE_LIST RangeList)
{
    InitializeListHead(&RangeList->ListHead);
    RangeList->Flags = 0;
    RangeList->Count = 0;
    RangeList->Stamp = 0;
}

/**********************************************************************
 * NAME							EXPORTED
 * 	RtlInvertRangeList
 *
 * DESCRIPTION
 *	Inverts a range list.
 *
 * ARGUMENTS
 *	InvertedRangeList	Inverted range list.
 *	RangeList		Range list.
 *
 * RETURN VALUE
 *	Status
 *
 * @implemented
 */
NTAPI NTSTATUS RtlInvertRangeList(OUT PRTL_RANGE_LIST InvertedRangeList,
				  IN PRTL_RANGE_LIST RangeList)
{
    PRTL_RANGE_ENTRY Previous;
    PRTL_RANGE_ENTRY Current;
    PLIST_ENTRY Entry;
    NTSTATUS Status;

    /* Add leading and intermediate ranges */
    Previous = NULL;
    Entry = RangeList->ListHead.Flink;
    while (Entry != &RangeList->ListHead) {
	Current = CONTAINING_RECORD(Entry, RTL_RANGE_ENTRY, Entry);

	if (Previous == NULL) {
	    if (Current->Range.Start != (ULONGLONG)0) {
		Status = RtlAddRange(InvertedRangeList, (ULONGLONG)0,
				     Current->Range.Start - 1, 0, 0, NULL, NULL);
		if (!NT_SUCCESS(Status))
		    return Status;
	    }
	} else {
	    if (Previous->Range.End + 1 != Current->Range.Start) {
		Status = RtlAddRange(InvertedRangeList, Previous->Range.End + 1,
				     Current->Range.Start - 1, 0, 0, NULL, NULL);
		if (!NT_SUCCESS(Status))
		    return Status;
	    }
	}

	Previous = Current;
	Entry = Entry->Flink;
    }

    /* Check if the list was empty */
    if (Previous == NULL) {
	/* We're done */
	return STATUS_SUCCESS;
    }

    /* Add trailing range */
    if (Previous->Range.End + 1 != (ULONGLONG)-1) {
	Status = RtlAddRange(InvertedRangeList, Previous->Range.End + 1, (ULONGLONG)-1, 0,
			     0, NULL, NULL);
	if (!NT_SUCCESS(Status))
	    return Status;
    }

    return STATUS_SUCCESS;
}

/**********************************************************************
 * NAME							EXPORTED
 * 	RtlIsRangeAvailable
 *
 * DESCRIPTION
 *	Checks whether a range is available or not.
 *
 * ARGUMENTS
 *	RangeList		Pointer to the range list.
 *	Start
 *	End
 *	Flags
 *	AttributeAvailableMask
 *	Context
 *	Callback
 *	Available
 *
 * RETURN VALUE
 *	Status
 *
 * TODO:
 *   - honor Flags and AttributeAvailableMask.
 *
 * @implemented
 */
NTAPI NTSTATUS RtlIsRangeAvailable(IN PRTL_RANGE_LIST RangeList, IN ULONGLONG Start,
				   IN ULONGLONG End, IN ULONG Flags,
				   IN UCHAR AttributeAvailableMask,
				   IN PVOID Context OPTIONAL,
				   IN PRTL_CONFLICT_RANGE_CALLBACK Callback OPTIONAL,
				   OUT PBOOLEAN Available)
{
    PRTL_RANGE_ENTRY Current;
    PLIST_ENTRY Entry;

    *Available = TRUE;

    Entry = RangeList->ListHead.Flink;
    while (Entry != &RangeList->ListHead) {
	Current = CONTAINING_RECORD(Entry, RTL_RANGE_ENTRY, Entry);

	if (!((Current->Range.Start >= End && Current->Range.End > End) ||
	      (Current->Range.Start <= Start && Current->Range.End < Start &&
	       (!(Flags & RTL_RANGE_SHARED) ||
		!(Current->Range.Flags & RTL_RANGE_SHARED))))) {
	    if (Callback != NULL) {
		*Available = Callback(Context, &Current->Range);
	    } else {
		*Available = FALSE;
	    }
	}

	Entry = Entry->Flink;
    }

    return STATUS_SUCCESS;
}

/**********************************************************************
 * NAME							EXPORTED
 * 	RtlMergeRangeList
 *
 * DESCRIPTION
 *	Merges two range lists.
 *
 * ARGUMENTS
 *	MergedRangeList	Resulting range list.
 *	RangeList1	First range list.
 *	RangeList2	Second range list
 *	Flags
 *
 * RETURN VALUE
 *	Status
 *
 * @implemented
 */
NTAPI NTSTATUS RtlMergeRangeLists(OUT PRTL_RANGE_LIST MergedRangeList,
				  IN PRTL_RANGE_LIST RangeList1,
				  IN PRTL_RANGE_LIST RangeList2, IN ULONG Flags)
{
    RTL_RANGE_LIST_ITERATOR Iterator;
    PRTL_RANGE Range;
    NTSTATUS Status;

    /* Copy range list 1 to the merged range list */
    Status = RtlCopyRangeList(MergedRangeList, RangeList1);
    if (!NT_SUCCESS(Status))
	return Status;

    /* Add range list 2 entries to the merged range list */
    Status = RtlGetFirstRange(RangeList2, &Iterator, &Range);
    if (!NT_SUCCESS(Status))
	return (Status == STATUS_NO_MORE_ENTRIES) ? STATUS_SUCCESS : Status;

    while (TRUE) {
	Status = RtlAddRange(MergedRangeList, Range->Start, Range->End, Range->Attributes,
			     Range->Flags | Flags, Range->UserData, Range->Owner);
	if (!NT_SUCCESS(Status))
	    break;

	Status = RtlGetNextRange(&Iterator, &Range, TRUE);
	if (!NT_SUCCESS(Status))
	    break;
    }

    return (Status == STATUS_NO_MORE_ENTRIES) ? STATUS_SUCCESS : Status;
}
