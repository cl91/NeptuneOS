#pragma once

#include <nt.h>
#include <wdm.h>

/*
 * An entry in the IRP queue. The ThisIrp handle points to the NTOS Executive's server-side
 * IO_REQUEST_PACKET, attached to the (server-side) device object.
 */
typedef struct _IRP_QUEUE_ENTRY {
    ULONG_PTR ThisIrp; /* (Temporarily) unique identifier (GLOBAL_HANDLE) of the IRP object. See halsvc.h */
    PIRP Irp; /* The client-side wdm IRP object allocated on the process heap */
    LIST_ENTRY Link;	/* List entry for the IRP queue */
    PVOID OutputBuffer;	/* Output buffer provided by the client process, mapped here */
    PVOID SavedStackPointer; /* Stack pointer at the time that KiYieldCoroutine yields execution */
    PVOID SavedInstructionPointer; /* Instruction pointer at the time that KiYieldCoroutine yields execution */
} IRP_QUEUE_ENTRY, *PIRP_QUEUE_ENTRY;
