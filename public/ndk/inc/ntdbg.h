#pragma once

#include <ntdef.h>
#include <ntioapi.h>
#include <ntlpc.h>
#include <ntrtl.h>

/*
 * Debug Object Access Masks
 */
#define DEBUG_OBJECT_WAIT_STATE_CHANGE      0x0001
#define DEBUG_OBJECT_ADD_REMOVE_PROCESS     0x0002
#define DEBUG_OBJECT_SET_INFORMATION        0x0004
#define DEBUG_OBJECT_ALL_ACCESS             (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x0F)

/*
 * Debug Event Flags
 */
#define DEBUG_EVENT_READ                  (0x01)
#define DEBUG_EVENT_NOWAIT                (0x02)
#define DEBUG_EVENT_INACTIVE              (0x04)
#define DEBUG_EVENT_RELEASE               (0x08)
#define DEBUG_EVENT_PROTECT_FAILED        (0x10)
#define DEBUG_EVENT_SUSPEND               (0x20)

/*
 * NtCreateDebugObject Flags
 */
#define DBGK_KILL_PROCESS_ON_EXIT         (0x1)
#define DBGK_ALL_FLAGS                    (DBGK_KILL_PROCESS_ON_EXIT)

/*
 * Debug Object Information Classes for NtQueryDebugObject
 */
typedef enum _DEBUG_OBJECT_INFORMATION_CLASS {
    DebugObjectUnusedInformation,
    DebugObjectKillProcessOnExitInformation
} DEBUG_OBJECT_INFORMATION_CLASS, *PDEBUG_OBJECT_INFORMATION_CLASS;

/*
 * Debug Message API Number
 */
typedef enum _DBGKM_APINUMBER {
    DbgKmExceptionApi = 0,
    DbgKmCreateThreadApi = 1,
    DbgKmCreateProcessApi = 2,
    DbgKmExitThreadApi = 3,
    DbgKmExitProcessApi = 4,
    DbgKmLoadDllApi = 5,
    DbgKmUnloadDllApi = 6,
    DbgKmErrorReportApi = 7,
    DbgKmMaxApiNumber = 8,
} DBGKM_APINUMBER;

/*
 * Debug Object Information Structures
 */
typedef struct _DEBUG_OBJECT_KILL_PROCESS_ON_EXIT_INFORMATION {
    ULONG KillProcessOnExit;
} DEBUG_OBJECT_KILL_PROCESS_ON_EXIT_INFORMATION, *PDEBUG_OBJECT_KILL_PROCESS_ON_EXIT_INFORMATION;

/*
 * Debug States
 */
typedef enum _DBG_STATE {
    DbgIdle,
    DbgReplyPending,
    DbgCreateThreadStateChange,
    DbgCreateProcessStateChange,
    DbgExitThreadStateChange,
    DbgExitProcessStateChange,
    DbgExceptionStateChange,
    DbgBreakpointStateChange,
    DbgSingleStepStateChange,
    DbgLoadDllStateChange,
    DbgUnloadDllStateChange
} DBG_STATE, *PDBG_STATE;

/*
 * Debug Message Structures
 */
typedef struct _DBGKM_EXCEPTION {
    EXCEPTION_RECORD ExceptionRecord;
    ULONG FirstChance;
} DBGKM_EXCEPTION, *PDBGKM_EXCEPTION;

typedef struct _DBGKM_CREATE_THREAD {
    ULONG SubSystemKey;
    PVOID StartAddress;
} DBGKM_CREATE_THREAD, *PDBGKM_CREATE_THREAD;

typedef struct _DBGKM_CREATE_PROCESS {
    ULONG SubSystemKey;
    HANDLE FileHandle;
    PVOID BaseOfImage;
    ULONG DebugInfoFileOffset;
    ULONG DebugInfoSize;
    DBGKM_CREATE_THREAD InitialThread;
} DBGKM_CREATE_PROCESS, *PDBGKM_CREATE_PROCESS;

typedef struct _DBGKM_EXIT_THREAD {
    NTSTATUS ExitStatus;
} DBGKM_EXIT_THREAD, *PDBGKM_EXIT_THREAD;

typedef struct _DBGKM_EXIT_PROCESS {
    NTSTATUS ExitStatus;
} DBGKM_EXIT_PROCESS, *PDBGKM_EXIT_PROCESS;

typedef struct _DBGKM_LOAD_DLL {
    HANDLE FileHandle;
    PVOID BaseOfDll;
    ULONG DebugInfoFileOffset;
    ULONG DebugInfoSize;
    PVOID NamePointer;
} DBGKM_LOAD_DLL, *PDBGKM_LOAD_DLL;

typedef struct _DBGKM_UNLOAD_DLL {
    PVOID BaseAddress;
} DBGKM_UNLOAD_DLL, *PDBGKM_UNLOAD_DLL;

/*
 * User-Mode Debug State Change Structure
 */
typedef struct _DBGUI_WAIT_STATE_CHANGE {
    DBG_STATE NewState;
    CLIENT_ID AppClientId;
    union {
	struct {
	    HANDLE HandleToThread;
	    DBGKM_CREATE_THREAD NewThread;
	} CreateThread;
	struct {
	    HANDLE HandleToProcess;
	    HANDLE HandleToThread;
	    DBGKM_CREATE_PROCESS NewProcess;
	} CreateProcessInfo;
	DBGKM_EXIT_THREAD ExitThread;
	DBGKM_EXIT_PROCESS ExitProcess;
	DBGKM_EXCEPTION Exception;
	DBGKM_LOAD_DLL LoadDll;
	DBGKM_UNLOAD_DLL UnloadDll;
    } StateInfo;
} DBGUI_WAIT_STATE_CHANGE, *PDBGUI_WAIT_STATE_CHANGE;

/*
 * LPC Debug Message
 */
typedef struct _DBGKM_MSG {
    PORT_MESSAGE h;
    DBGKM_APINUMBER ApiNumber;
    NTSTATUS ReturnedStatus;
    union {
	DBGKM_EXCEPTION Exception;
	DBGKM_CREATE_THREAD CreateThread;
	DBGKM_CREATE_PROCESS CreateProcess;
	DBGKM_EXIT_THREAD ExitThread;
	DBGKM_EXIT_PROCESS ExitProcess;
	DBGKM_LOAD_DLL LoadDll;
	DBGKM_UNLOAD_DLL UnloadDll;
    };
} DBGKM_MSG, *PDBGKM_MSG;

#ifndef _NTOSKRNL_

/*
 * Debug Object Native Calls
 */
NTAPI NTSYSAPI NTSTATUS NtCreateDebugObject(OUT PHANDLE DebugHandle,
					    IN ACCESS_MASK DesiredAccess,
					    IN POBJECT_ATTRIBUTES ObjectAttributes,
					    IN ULONG Flags);

NTAPI NTSYSAPI NTSTATUS NtDebugActiveProcess(IN HANDLE Process,
					     IN HANDLE DebugObject);

NTAPI NTSYSAPI NTSTATUS NtDebugContinue(IN HANDLE DebugObject,
					IN PCLIENT_ID AppClientId,
					IN NTSTATUS ContinueStatus);

NTAPI NTSYSAPI NTSTATUS NtWaitForDebugEvent(IN HANDLE DebugObject,
					    IN BOOLEAN Alertable,
					    IN OPTIONAL PLARGE_INTEGER Timeout,
					    OUT PDBGUI_WAIT_STATE_CHANGE StateChange);

NTAPI NTSYSAPI NTSTATUS NtRemoveProcessDebug(IN HANDLE Process,
					     IN HANDLE DebugObject);

NTAPI NTSYSAPI NTSTATUS NtSetInformationDebugObject(IN HANDLE DebugObject,
						    IN DEBUG_OBJECT_INFORMATION_CLASS InfoClass,
						    IN PVOID Information,
						    IN ULONG InformationLength,
						    OUT OPTIONAL PULONG ReturnLength);

/*
 * Debug UI Routines
 */
NTAPI NTSYSAPI NTSTATUS DbgUiConnectToDbg(VOID);

NTAPI NTSYSAPI NTSTATUS DbgUiContinue(IN PCLIENT_ID ClientId, IN NTSTATUS ContinueStatus);

NTAPI NTSYSAPI NTSTATUS DbgUiDebugActiveProcess(IN HANDLE Process);

NTAPI NTSYSAPI NTSTATUS DbgUiStopDebugging(IN HANDLE Process);

NTAPI NTSYSAPI NTSTATUS DbgUiWaitStateChange(IN PDBGUI_WAIT_STATE_CHANGE Change,
					     IN PLARGE_INTEGER TimeOut);

NTAPI NTSYSAPI VOID DbgUiRemoteBreakin(VOID);

NTAPI NTSYSAPI NTSTATUS DbgUiIssueRemoteBreakin(IN HANDLE Process);

NTAPI NTSYSAPI HANDLE DbgUiGetThreadDebugObject(VOID);

#endif	/* !_NTOSKRNL_ */

#if defined(_NTOSKRNL_) || defined(_NTDDK_)

/*
 * Helper functions for the IO resource requirements list
 */

FORCEINLINE PCHAR CmDbgResourceTypeToText(IN UCHAR Type)
{
    /* What kind of resource it this? */
    switch (Type) {
	/* Pick the correct identifier string based on the type */
    case CmResourceTypeDeviceSpecific:
	return "CmResourceTypeDeviceSpecific";
    case CmResourceTypePort:
	return "CmResourceTypePort";
    case CmResourceTypeInterrupt:
	return "CmResourceTypeInterrupt";
    case CmResourceTypeMemory:
	return "CmResourceTypeMemory";
    case CmResourceTypeDma:
	return "CmResourceTypeDma";
    case CmResourceTypeBusNumber:
	return "CmResourceTypeBusNumber";
    case CmResourceTypeMemoryLarge:
	return "CmResourceTypeMemoryLarge";
    case CmResourceTypeConfigData:
	return "CmResourceTypeConfigData";
    case CmResourceTypeDevicePrivate:
	return "CmResourceTypeDevicePrivate";
    case CmResourceTypePcCardConfig:
	return "CmResourceTypePcCardConfig";
    default:
	return "*** INVALID RESOURCE TYPE ***";
    }
}

FORCEINLINE PCSTR IoDbgResourceOptionToStr(ULONG Option)
{
    if (!Option) {
	return "required";
    } else if (Option & IO_RESOURCE_PREFERRED) {
	return "preferred";
    } else if (Option & IO_RESOURCE_ALTERNATIVE) {
	return "alternative";
    } else {
	return "invalid";
    }
}

FORCEINLINE VOID IoDbgPrintResourceDescriptor(IN PIO_RESOURCE_DESCRIPTOR Descriptor)
{
    /* Print out the header */
    DbgPrint("     IoResource Descriptor dump:  Descriptor @ %p\n", Descriptor);
    DbgPrint("        Option           = 0x%x (%s)\n", Descriptor->Option,
	     IoDbgResourceOptionToStr(Descriptor->Option));
    DbgPrint("        Type             = %u (%s)\n", Descriptor->Type,
	     CmDbgResourceTypeToText(Descriptor->Type));
    DbgPrint("        ShareDisposition = %u\n", Descriptor->ShareDisposition);
    DbgPrint("        Flags            = 0x%04X\n", Descriptor->Flags);

    /* Loop private data */
    PULONG Data = Descriptor->DevicePrivate.Data;
    for (ULONG i = 0; i < 6; i += 3) {
	/* Dump it in 32-bit triplets */
	DbgPrint("        Data[%u] = %08x  %08x  %08x\n", i, Data[i], Data[i+1], Data[i+2]);
    }
}

FORCEINLINE VOID IoDbgPrintResouceRequirementsList(IN PIO_RESOURCE_REQUIREMENTS_LIST ReqList)
{
    /* Make sure there's a list */
    if (!ReqList)
	return;

    /* Grab the main list and the alternates as well */
    ULONG AlternativeLists = ReqList->AlternativeLists;
    PIO_RESOURCE_LIST List = ReqList->List;

    /* Print out the initial header*/
    DbgPrint("  IO_RESOURCE_REQUIREMENTS_LIST:\n");
    DbgPrint("     InterfaceType        %d\n", ReqList->InterfaceType);
    DbgPrint("     BusNumber            0x%x\n", ReqList->BusNumber);
    if (ReqList->InterfaceType == PCIBus) {
	DbgPrint("     SlotNumber           %d (0x%x), (d/f = 0x%x/0x%x)\n",
		ReqList->SlotNumber, ReqList->SlotNumber,
		((PCI_SLOT_NUMBER *)&ReqList->SlotNumber)->Bits.DeviceNumber,
		((PCI_SLOT_NUMBER *)&ReqList->SlotNumber)->Bits.FunctionNumber);
    } else {
	DbgPrint("     SlotNumber           %d (0x%x)\n",
		ReqList->SlotNumber, ReqList->SlotNumber);
    }
    DbgPrint("     AlternativeLists     %u\n", AlternativeLists);

    /* Scan alternative lists */
    for (ULONG i = 0; i < AlternativeLists; i++) {
	/* Get the descriptor array, and the count of descriptors */
	PIO_RESOURCE_DESCRIPTOR Descriptor = List->Descriptors;
	ULONG Count = List->Count;

	/* Print out each descriptor */
	DbgPrint("     List[%u].Count = %u\n", i, Count);
	while (Count--)
	    IoDbgPrintResourceDescriptor(Descriptor++);

	/* Should've reached a new list now */
	List = (PIO_RESOURCE_LIST)Descriptor;
    }

    /* Terminate the dump */
    DbgPrint("\n");
}

/*
 * Usage note:
 *
 * As there can be only one variable-sized CM_PARTIAL_RESOURCE_DESCRIPTOR
 * in the list (and it must be the last one), a correct looping through resources
 * can look like this:
 *
 *   PCM_FULL_RESOURCE_DESCRIPTOR FullDesc = &ResourceList->List[0];
 *   for (ULONG i = 0; i < ResourceList->Count;
 *        i++, FullDesc = CmiGetNextResourceDescriptor(FullDesc)) {
 *       for (ULONG j = 0; j < FullDesc->PartialResourceList.Count; j++) {
 *           PartialDesc = &FullDesc->PartialResourceList.PartialDescriptors[j];
 *            // work with PartialDesc
 *       }
 *   }
 */
FORCEINLINE PCM_PARTIAL_RESOURCE_DESCRIPTOR
CmGetNextPartialDescriptor(IN CONST CM_PARTIAL_RESOURCE_DESCRIPTOR *Partial)
{
    /* Assume the descriptors are the fixed size ones */
    const CM_PARTIAL_RESOURCE_DESCRIPTOR *Next = Partial + 1;

    /* But check if this is actually a variable-sized descriptor */
    if (Partial->Type == CmResourceTypeDeviceSpecific) {
	/* Add the size of the variable section as well */
	Next = (PCM_PARTIAL_RESOURCE_DESCRIPTOR)((ULONG_PTR)Next +
						 Partial->DeviceSpecificData.DataSize);
	ASSERT(Next >= Partial + 1);
    }

    /* Now the correct pointer has been computed, return it */
    return (PCM_PARTIAL_RESOURCE_DESCRIPTOR)Next;
}

FORCEINLINE PCM_FULL_RESOURCE_DESCRIPTOR
CmGetNextResourceDescriptor(IN CONST CM_FULL_RESOURCE_DESCRIPTOR *Res)
{
    /* Calculate the location of the last partial descriptor, which can have a
       variable size! */
    const CM_PARTIAL_RESOURCE_DESCRIPTOR *Last =
	&Res->PartialResourceList.PartialDescriptors[Res->PartialResourceList.Count - 1];

    /* Next full resource descriptor follows the last partial descriptor */
    return (PCM_FULL_RESOURCE_DESCRIPTOR)CmGetNextPartialDescriptor(Last);
}

FORCEINLINE ULONG CmGetResourceListSize(IN PCM_RESOURCE_LIST Res)
{
    if (!Res) {
	return 0;
    }
    ULONG ResSize = sizeof(CM_RESOURCE_LIST) + Res->Count * sizeof(CM_FULL_RESOURCE_DESCRIPTOR);
    PCM_FULL_RESOURCE_DESCRIPTOR Desc = Res->List;
    for (ULONG i = 0; i < Res->Count; i++) {
	ResSize += Desc->PartialResourceList.Count * sizeof(CM_PARTIAL_RESOURCE_DESCRIPTOR);
	Desc = CmGetNextResourceDescriptor(Desc);
    }
    return ResSize;
}

FORCEINLINE VOID CmDbgPrintResourceDescriptor(IN PCM_PARTIAL_RESOURCE_DESCRIPTOR Res)
{
    /* Dump all the data in the partial */
    DbgPrint("     Partial Resource Descriptor @ %p\n", Res);
    DbgPrint("        Type             = %u (%s)\n", Res->Type,
	     CmDbgResourceTypeToText(Res->Type));
    DbgPrint("        ShareDisposition = %u\n", Res->ShareDisposition);
    DbgPrint("        Flags            = 0x%04X\n", Res->Flags);
    DbgPrint("        Data[%d] = %08x  %08x  %08x\n", 0,
	     Res->Generic.Start.LowPart,
	     Res->Generic.Start.HighPart, Res->Generic.Length);
}

FORCEINLINE VOID CmDbgPrintResourceList(IN PCM_RESOURCE_LIST PartialList)
{
    /* Make sure there's something to dump */
    if (!PartialList)
	return;

    /* Get the full list count */
    ULONG ListCount = PartialList->Count;
    PCM_FULL_RESOURCE_DESCRIPTOR FullDescriptor = PartialList->List;
    DbgPrint("  CM_RESOURCE_LIST (List Count = %u)\n",
	     PartialList->Count);

    /* Loop full list */
    for (ULONG i = 0; i < ListCount; i++) {
	/* Loop full descriptor */
	DbgPrint("     InterfaceType        %d\n", FullDescriptor->InterfaceType);
	DbgPrint("     BusNumber            0x%x\n", FullDescriptor->BusNumber);

	/* Get partial count and loop partials */
	PCM_PARTIAL_RESOURCE_DESCRIPTOR PartialDescriptor =
	    FullDescriptor->PartialResourceList.PartialDescriptors;
	for (ULONG Count = FullDescriptor->PartialResourceList.Count; Count; Count--) {
	    /* Print each partial resource descriptor */
	    CmDbgPrintResourceDescriptor(PartialDescriptor);
	    PartialDescriptor = CmGetNextPartialDescriptor(PartialDescriptor);
	}

	/* Go to the next full descriptor */
	FullDescriptor = (PCM_FULL_RESOURCE_DESCRIPTOR)PartialDescriptor;
    }

    /* Done printing data */
    DbgPrint("\n");
}

#endif	/* defined(_NTOSKRNL_) || defined(_NTDDK_) */
