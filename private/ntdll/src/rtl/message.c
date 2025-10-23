/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS system libraries
 * FILE:            lib/rtl/message.c
 * PURPOSE:         Message table functions
 * PROGRAMMERS:     Eric Kohl
 */

/* INCLUDES *****************************************************************/

#include <nt.h>

/* Comment this to enable debug logging */
#undef DPRINT
#define DPRINT(...)

/* FUNCTIONS *****************************************************************/

/*
 * @implemented
 */
NTAPI NTSTATUS RtlFindMessage(IN PVOID BaseAddress, IN ULONG Type,
			      IN ULONG Language, IN ULONG MessageId,
			      OUT PMESSAGE_RESOURCE_ENTRY *MessageResourceEntry)
{
    PIMAGE_RESOURCE_DATA_ENTRY ResourceDataEntry;
    PMESSAGE_RESOURCE_DATA MessageTable;
    NTSTATUS Status;
    ULONG EntryOffset = 0, IdOffset = 0;
    PMESSAGE_RESOURCE_ENTRY MessageEntry;
    ULONG i;

    DPRINT("RtlFindMessage(): BaseAddress %p Type %d Language 0x%x MessageId 0x%x\n",
	   BaseAddress, Type, Language, MessageId);

    LDR_RESOURCE_INFO ResourceInfo = {
	.Type = Type,
	.Name = 1,
	.Language = Language
    };

    Status = LdrFindResource_U(BaseAddress, &ResourceInfo, RESOURCE_DATA_LEVEL,
			       &ResourceDataEntry);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    DPRINT("ResourceDataEntry: %p\n", ResourceDataEntry);

    Status = LdrAccessResource(BaseAddress, ResourceDataEntry, (PVOID *)&MessageTable,
			       NULL);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    DPRINT("MessageTable: %p\n", MessageTable);

    DPRINT("NumberOfBlocks %u\n", MessageTable->NumberOfBlocks);
    for (i = 0; i < MessageTable->NumberOfBlocks; i++) {
	DPRINT("LoId 0x%08x  HiId 0x%08x  Offset 0x%08x\n",
	       MessageTable->Blocks[i].LowId, MessageTable->Blocks[i].HighId,
	       MessageTable->Blocks[i].OffsetToEntries);
    }

    for (i = 0; i < MessageTable->NumberOfBlocks; i++) {
	if ((MessageId >= MessageTable->Blocks[i].LowId) &&
	    (MessageId <= MessageTable->Blocks[i].HighId)) {
	    EntryOffset = MessageTable->Blocks[i].OffsetToEntries;
	    IdOffset = MessageId - MessageTable->Blocks[i].LowId;
	    break;
	}

	if (MessageId < MessageTable->Blocks[i].LowId) {
	    return STATUS_MESSAGE_NOT_FOUND;
	}
    }

    if (MessageTable->NumberOfBlocks <= i) {
	return STATUS_MESSAGE_NOT_FOUND;
    }

    MessageEntry = (PMESSAGE_RESOURCE_ENTRY)((PUCHAR)MessageTable +
					     MessageTable->Blocks[i].OffsetToEntries);

    DPRINT("EntryOffset 0x%08x\n", EntryOffset);
    DPRINT("IdOffset 0x%08x\n", IdOffset);

    DPRINT("MessageEntry: %p\n", MessageEntry);
    for (i = 0; i < IdOffset; i++) {
	MessageEntry = (PMESSAGE_RESOURCE_ENTRY)((PUCHAR)MessageEntry +
						 (ULONG)MessageEntry->Length);
    }

    if (MessageEntry->Flags == 0) {
	DPRINT("AnsiText: %s\n", MessageEntry->Text);
    } else {
	DPRINT("UnicodeText: %ws\n", (PWSTR)MessageEntry->Text);
    }

    if (MessageResourceEntry != NULL) {
	*MessageResourceEntry = MessageEntry;
    }

    return STATUS_SUCCESS;
}

/*
 * @unimplemented
 */
NTSTATUS
NTAPI
RtlFormatMessageEx(IN PWSTR Message, IN ULONG MaxWidth OPTIONAL, IN BOOLEAN IgnoreInserts,
		   IN BOOLEAN ArgumentsAreAnsi, IN BOOLEAN ArgumentsAreAnArray,
		   IN va_list *Arguments, OUT PWSTR Buffer, IN ULONG BufferSize,
		   OUT PULONG ReturnLength OPTIONAL, IN ULONG Flags)
{
    DPRINT1("RtlFormatMessage(%ws, %u, %s, %s, %s, %p, %p, %u, %p, %x)\n", Message,
	    MaxWidth, IgnoreInserts ? "TRUE" : "FALSE",
	    ArgumentsAreAnsi ? "TRUE" : "FALSE", ArgumentsAreAnArray ? "TRUE" : "FALSE",
	    Arguments, Buffer, BufferSize, ReturnLength, Flags);

    UNIMPLEMENTED;
    return STATUS_NOT_IMPLEMENTED;
}

/**********************************************************************
 *  RtlFormatMessage  (NTDLL.@)
 *
 * Formats a message (similar to sprintf).
 *
 * PARAMS
 *   Message             [I] Message to format.
 *   MaxWidth            [I] Maximum width in characters of each output line (optional).
 *   IgnoreInserts       [I] Whether to copy the message without processing inserts.
 *   ArgumentsAreAnsi    [I] Whether Arguments may have ANSI strings.
 *   ArgumentsAreAnArray [I] Whether Arguments is actually an array rather than a va_list *.
 *   Arguments           [I]
 *   Buffer              [O] Buffer to store processed message in.
 *   BufferSize          [I] Size of Buffer (in bytes).
 *   ReturnLength        [O] Size of the formatted message (in bytes; optional).
 *
 * RETURNS
 *      NTSTATUS code.
 *
 * @implemented
 */
NTSTATUS
NTAPI
RtlFormatMessage(IN PWSTR Message, IN ULONG MaxWidth OPTIONAL, IN BOOLEAN IgnoreInserts,
		 IN BOOLEAN ArgumentsAreAnsi, IN BOOLEAN ArgumentsAreAnArray,
		 IN va_list *Arguments, OUT PWSTR Buffer, IN ULONG BufferSize,
		 OUT PULONG ReturnLength OPTIONAL)
{
    /* Call the extended API */
    return RtlFormatMessageEx(Message, MaxWidth, IgnoreInserts, ArgumentsAreAnsi,
			      ArgumentsAreAnArray, Arguments, Buffer, BufferSize,
			      ReturnLength, 0);
}

/* EOF */
