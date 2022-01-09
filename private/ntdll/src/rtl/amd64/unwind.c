/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS system libraries
 * PURPOSE:         Unwinding related functions
 * PROGRAMMER:      Timo Kreuzer (timo.kreuzer@reactos.org)
 */

/* INCLUDES *****************************************************************/

#include "../rtlp.h"

#define UNWIND_HISTORY_TABLE_NONE 0
#define UNWIND_HISTORY_TABLE_GLOBAL 1
#define UNWIND_HISTORY_TABLE_LOCAL 2

#define UWOP_PUSH_NONVOL 0
#define UWOP_ALLOC_LARGE 1
#define UWOP_ALLOC_SMALL 2
#define UWOP_SET_FPREG 3
#define UWOP_SAVE_NONVOL 4
#define UWOP_SAVE_NONVOL_FAR 5
#define UWOP_EPILOG 6		/* previously UWOP_SAVE_XMM */
#define UWOP_SPARE_CODE 7	/* previously UWOP_SAVE_XMM_FAR */
#define UWOP_SAVE_XMM128 8
#define UWOP_SAVE_XMM128_FAR 9
#define UWOP_PUSH_MACHFRAME 10


typedef unsigned char UBYTE;

typedef union _UNWIND_CODE {
    struct {
	UBYTE CodeOffset;
	UBYTE UnwindOp:4;
	UBYTE OpInfo:4;
    };
    USHORT FrameOffset;
} UNWIND_CODE, *PUNWIND_CODE;

typedef struct _UNWIND_INFO {
    UBYTE Version:3;
    UBYTE Flags:5;
    UBYTE SizeOfProlog;
    UBYTE CountOfCodes;
    UBYTE FrameRegister:4;
    UBYTE FrameOffset:4;
    UNWIND_CODE UnwindCode[1];
/*    union {
      OPTIONAL ULONG ExceptionHandler;
      OPTIONAL ULONG FunctionEntry;
      };
      OPTIONAL ULONG ExceptionData[];
*/
} UNWIND_INFO, *PUNWIND_INFO;

/* FUNCTIONS *****************************************************************/

/*! RtlLookupFunctionTable
 * \brief Locates the table of RUNTIME_FUNCTION entries for a code address.
 * \param ControlPc
 *            Address of the code, for which the table should be searched.
 * \param ImageBase
 *            Pointer to a DWORD64 that receives the base address of the
 *            corresponding executable image.
 * \param Length
 *            Pointer to an ULONG that receives the number of table entries
 *            present in the table.
 */
NTAPI PRUNTIME_FUNCTION RtlLookupFunctionTable(IN DWORD64 ControlPc,
					       OUT PDWORD64 ImageBase,
					       OUT PULONG Length)
{
    PVOID Table;
    ULONG Size;

    /* Find corresponding file header from code address */
    if (!RtlPcToFileHeader((PVOID) ControlPc, (PVOID *) ImageBase)) {
	/* Nothing found */
	return NULL;
    }

    /* Locate the exception directory */
    Table = RtlImageDirectoryEntryToData((PVOID) * ImageBase,
					 TRUE,
					 IMAGE_DIRECTORY_ENTRY_EXCEPTION,
					 &Size);

    /* Return the number of entries */
    *Length = Size / sizeof(RUNTIME_FUNCTION);

    /* Return the address of the table */
    return Table;
}

/*! RtlLookupFunctionEntry
 * \brief Locates the RUNTIME_FUNCTION entry corresponding to a code address.
 * \ref http://msdn.microsoft.com/en-us/library/ms680597(VS.85).aspx
 * \todo Implement HistoryTable
 */
NTAPI PRUNTIME_FUNCTION RtlLookupFunctionEntry(IN DWORD64 ControlPc,
					       OUT PDWORD64 ImageBase,
					       OUT PUNWIND_HISTORY_TABLE HistoryTable)
{
    PRUNTIME_FUNCTION FunctionTable, FunctionEntry;
    ULONG TableLength;
    ULONG IndexLo, IndexHi, IndexMid;

    /* Find the corresponding table */
    FunctionTable = RtlLookupFunctionTable(ControlPc, ImageBase, &TableLength);

    /* Fail, if no table is found */
    if (!FunctionTable) {
	return NULL;
    }

    /* Use relative virtual address */
    ControlPc -= *ImageBase;

    /* Do a binary search */
    IndexLo = 0;
    IndexHi = TableLength;
    while (IndexHi > IndexLo) {
	IndexMid = (IndexLo + IndexHi) / 2;
	FunctionEntry = &FunctionTable[IndexMid];

	if (ControlPc < FunctionEntry->BeginAddress) {
	    /* Continue search in lower half */
	    IndexHi = IndexMid;
	} else if (ControlPc >= FunctionEntry->EndAddress) {
	    /* Continue search in upper half */
	    IndexLo = IndexMid + 1;
	} else {
	    /* ControlPc is within limits, return entry */
	    return FunctionEntry;
	}
    }

    /* Nothing found, return NULL */
    return NULL;
}

NTAPI BOOLEAN RtlAddFunctionTable(IN PRUNTIME_FUNCTION FunctionTable,
				  IN DWORD EntryCount,
				  IN DWORD64 BaseAddress)
{
    UNIMPLEMENTED;
    return FALSE;
}

NTAPI BOOLEAN RtlDeleteFunctionTable(IN PRUNTIME_FUNCTION FunctionTable)
{
    UNIMPLEMENTED;
    return FALSE;
}

NTAPI BOOLEAN RtlInstallFunctionTableCallback(IN DWORD64 TableIdentifier,
					      IN DWORD64 BaseAddress,
					      IN DWORD Length,
					      IN PGET_RUNTIME_FUNCTION_CALLBACK Callback,
					      IN PVOID Context,
					      IN PCWSTR OutOfProcessCallbackDll)
{
    UNIMPLEMENTED;
    return FALSE;
}

static inline ULONG UnwindOpSlots(IN UNWIND_CODE UnwindCode)
{
    const UCHAR UnwindOpExtraSlotTable[] = {
	0,			// UWOP_PUSH_NONVOL
	1,			// UWOP_ALLOC_LARGE (or 3, special cased in lookup code)
	0,			// UWOP_ALLOC_SMALL
	0,			// UWOP_SET_FPREG
	1,			// UWOP_SAVE_NONVOL
	2,			// UWOP_SAVE_NONVOL_FAR
	1,			// UWOP_EPILOG // previously UWOP_SAVE_XMM
	2,			// UWOP_SPARE_CODE // previously UWOP_SAVE_XMM_FAR
	1,			// UWOP_SAVE_XMM128
	2,			// UWOP_SAVE_XMM128_FAR
	0,			// UWOP_PUSH_MACHFRAME
	2,			// UWOP_SET_FPREG_LARGE
    };

    if ((UnwindCode.UnwindOp == UWOP_ALLOC_LARGE) && (UnwindCode.OpInfo != 0)) {
	return 3;
    } else {
	return UnwindOpExtraSlotTable[UnwindCode.UnwindOp] + 1;
    }
}

static inline void SetReg(IN OUT PCONTEXT Context,
			  IN BYTE Reg,
			  IN DWORD64 Value)
{
    ((DWORD64 *) (&Context->Rax))[Reg] = Value;
}

static inline void SetRegFromStackValue(IN OUT PCONTEXT Context,
					IN OUT OPTIONAL PKNONVOLATILE_CONTEXT_POINTERS ContextPointers,
					IN BYTE Reg,
					IN PDWORD64 ValuePointer)
{
    SetReg(Context, Reg, *ValuePointer);
    if (ContextPointers != NULL) {
	ContextPointers->IntegerContext[Reg] = ValuePointer;
    }
}

static inline DWORD64 GetReg(IN PCONTEXT Context,
			     IN BYTE Reg)
{
    return ((DWORD64 *) (&Context->Rax))[Reg];
}

static inline void PopReg(IN OUT PCONTEXT Context,
			  IN OUT OPTIONAL PKNONVOLATILE_CONTEXT_POINTERS ContextPointers,
			  IN BYTE Reg)
{
    SetRegFromStackValue(Context, ContextPointers, Reg, (PDWORD64) Context->Rsp);
    Context->Rsp += sizeof(DWORD64);
}

static inline void SetXmmReg(IN OUT PCONTEXT Context,
			     IN BYTE Reg,
			     IN M128A Value)
{
    ((M128A *) (&Context->Xmm0))[Reg] = Value;
}

static inline void SetXmmRegFromStackValue(OUT PCONTEXT Context,
					   IN OUT OPTIONAL PKNONVOLATILE_CONTEXT_POINTERS ContextPointers,
					   IN BYTE Reg,
					   IN M128A *ValuePointer)
{
    SetXmmReg(Context, Reg, *ValuePointer);
    if (ContextPointers != NULL) {
	ContextPointers->FloatingContext[Reg] = ValuePointer;
    }
}

static inline M128A GetXmmReg(IN PCONTEXT Context,
			      IN BYTE Reg)
{
    return ((M128A *) (&Context->Xmm0))[Reg];
}

/*! RtlpTryToUnwindEpilog
 * \brief Helper function that tries to unwind epilog instructions.
 * \return TRUE if we have been in an epilog and it could be unwound.
 *         FALSE if the instructions were not allowed for an epilog.
 * \ref
 *  https://docs.microsoft.com/en-us/cpp/build/unwind-procedure
 *  https://docs.microsoft.com/en-us/cpp/build/prolog-and-epilog
 * \todo
 *  - Test and compare with Windows behaviour
 */
static inline BOOLEAN RtlpTryToUnwindEpilog(IN OUT PCONTEXT Context,
					    IN OUT OPTIONAL PKNONVOLATILE_CONTEXT_POINTERS ContextPointers,
					    IN ULONG64 ImageBase,
					    IN PRUNTIME_FUNCTION FunctionEntry)
{
    CONTEXT LocalContext;
    BYTE *InstrPtr;
    DWORD Instr;
    BYTE Reg, Mod;
    ULONG64 EndAddress;

    /* Make a local copy of the context */
    LocalContext = *Context;

    InstrPtr = (BYTE *) LocalContext.Rip;

    /* Check if first instruction of epilog is "add rsp, x" */
    Instr = *(DWORD *) InstrPtr;
    if ((Instr & 0x00fffdff) == 0x00c48148) {
	if ((Instr & 0x0000ff00) == 0x8300) {
	    /* This is "add rsp, 0x??" */
	    LocalContext.Rsp += Instr >> 24;
	    InstrPtr += 4;
	} else {
	    /* This is "add rsp, 0x???????? */
	    LocalContext.Rsp += *(DWORD *) (InstrPtr + 3);
	    InstrPtr += 7;
	}
    }
    /* Check if first instruction of epilog is "lea rsp, ..." */
    else if ((Instr & 0x38fffe) == 0x208d48) {
	/* Get the register */
	Reg = ((Instr << 8) | (Instr >> 16)) & 0x7;

	LocalContext.Rsp = GetReg(&LocalContext, Reg);

	/* Get adressing mode */
	Mod = (Instr >> 22) & 0x3;
	if (Mod == 0) {
	    /* No displacement */
	    InstrPtr += 3;
	} else if (Mod == 1) {
	    /* 1 byte displacement */
	    LocalContext.Rsp += Instr >> 24;
	    InstrPtr += 4;
	} else if (Mod == 2) {
	    /* 4 bytes displacement */
	    LocalContext.Rsp += *(DWORD *) (InstrPtr + 3);
	    InstrPtr += 7;
	}
    }

    /* Loop the following instructions before the ret */
    EndAddress = FunctionEntry->EndAddress + ImageBase - 1;
    while ((DWORD64) InstrPtr < EndAddress) {
	Instr = *(DWORD *) InstrPtr;

	/* Check for a simple pop */
	if ((Instr & 0xf8) == 0x58) {
	    /* Opcode pops a basic register from stack */
	    Reg = Instr & 0x7;
	    PopReg(&LocalContext, ContextPointers, Reg);
	    InstrPtr++;
	    continue;
	}

	/* Check for REX + pop */
	if ((Instr & 0xf8fb) == 0x5841) {
	    /* Opcode is pop r8 .. r15 */
	    Reg = ((Instr >> 8) & 0x7) + 8;
	    PopReg(&LocalContext, ContextPointers, Reg);
	    InstrPtr += 2;
	    continue;
	}

	/* Opcode not allowed for Epilog */
	return FALSE;
    }

    // check for popfq

    // also allow end with jmp imm, jmp [target], iretq

    /* Check if we are at the ret instruction */
    if ((DWORD64) InstrPtr != EndAddress) {
	/* If we went past the end of the function, something is broken! */
	ASSERT((DWORD64) InstrPtr <= EndAddress);
	return FALSE;
    }

    /* Make sure this is really a ret instruction */
    if (*InstrPtr != 0xc3) {
	ASSERT(FALSE);
	return FALSE;
    }

    /* Unwind is finished, pop new Rip from Stack */
    LocalContext.Rip = *(DWORD64 *) LocalContext.Rsp;
    LocalContext.Rsp += sizeof(DWORD64);

    *Context = LocalContext;
    return TRUE;
}

/*!GetEstablisherFrame
 *
 * \ref https://docs.microsoft.com/en-us/cpp/build/unwind-data-definitions-in-c
*/
static ULONG64 GetEstablisherFrame(IN PCONTEXT Context,
				   IN PUNWIND_INFO UnwindInfo,
				   IN ULONG_PTR CodeOffset)
{
    ULONG i;

    /* Check if we have a frame register */
    if (UnwindInfo->FrameRegister == 0) {
	/* No frame register means we use Rsp */
	return Context->Rsp;
    }

    if ((CodeOffset >= UnwindInfo->SizeOfProlog) ||
	((UnwindInfo->Flags & UNW_FLAG_CHAININFO) != 0)) {
	return GetReg(Context, UnwindInfo->FrameRegister) -
	    UnwindInfo->FrameOffset * 16;
    }

    /* Loop all unwind ops */
    for (i = 0;
	 i < UnwindInfo->CountOfCodes;
	 i += UnwindOpSlots(UnwindInfo->UnwindCode[i])) {
	/* Check for SET_FPREG */
	if (UnwindInfo->UnwindCode[i].UnwindOp == UWOP_SET_FPREG) {
	    return GetReg(Context, UnwindInfo->FrameRegister) -
		UnwindInfo->FrameOffset * 16;
	}
    }

    return Context->Rsp;
}

PEXCEPTION_ROUTINE NTAPI RtlVirtualUnwind(IN ULONG HandlerType,
					  IN ULONG64 ImageBase,
					  IN ULONG64 ControlPc,
					  IN PRUNTIME_FUNCTION FunctionEntry,
					  IN OUT PCONTEXT Context,
					  OUT PVOID *HandlerData,
					  OUT PULONG64 EstablisherFrame,
					  IN OUT OPTIONAL PKNONVOLATILE_CONTEXT_POINTERS ContextPointers)
{
    PUNWIND_INFO UnwindInfo;
    ULONG_PTR CodeOffset;
    ULONG i, Offset;
    UNWIND_CODE UnwindCode;
    BYTE Reg;
    PULONG LanguageHandler;

    /* Use relative virtual address */
    ControlPc -= ImageBase;

    /* Sanity checks */
    if ((ControlPc < FunctionEntry->BeginAddress) || (ControlPc >= FunctionEntry->EndAddress)) {
	return NULL;
    }

    /* Get a pointer to the unwind info */
    UnwindInfo = RVA(ImageBase, FunctionEntry->UnwindData);

    /* The language specific handler data follows the unwind info */
    LanguageHandler = ALIGN_UP_POINTER_BY(&UnwindInfo->UnwindCode[UnwindInfo->CountOfCodes],
					  sizeof(ULONG));
    *HandlerData = (LanguageHandler + 1);

    /* Calculate relative offset to function start */
    CodeOffset = ControlPc - FunctionEntry->BeginAddress;

    *EstablisherFrame = GetEstablisherFrame(Context, UnwindInfo, CodeOffset);

    /* Check if we are in the function epilog and try to finish it */
    if (CodeOffset > UnwindInfo->SizeOfProlog) {
	if (RtlpTryToUnwindEpilog
	    (Context, ContextPointers, ImageBase, FunctionEntry)) {
	    /* There's no exception routine */
	    return NULL;
	}
    }

    /* Skip all Ops with an offset greater than the current Offset */
    i = 0;
    while ((i < UnwindInfo->CountOfCodes) &&
	   (UnwindInfo->UnwindCode[i].CodeOffset > CodeOffset)) {
	i += UnwindOpSlots(UnwindInfo->UnwindCode[i]);
    }

RepeatChainedInfo:
    /* Process the remaining unwind ops */
    while (i < UnwindInfo->CountOfCodes) {
	UnwindCode = UnwindInfo->UnwindCode[i];
	switch (UnwindCode.UnwindOp) {
	case UWOP_PUSH_NONVOL:
	    Reg = UnwindCode.OpInfo;
	    PopReg(Context, ContextPointers, Reg);
	    i++;
	    break;

	case UWOP_ALLOC_LARGE:
	    if (UnwindCode.OpInfo) {
		Offset = *(ULONG *) (&UnwindInfo->UnwindCode[i + 1]);
		Context->Rsp += Offset;
		i += 3;
	    } else {
		Offset = UnwindInfo->UnwindCode[i + 1].FrameOffset;
		Context->Rsp += Offset * 8;
		i += 2;
	    }
	    break;

	case UWOP_ALLOC_SMALL:
	    Context->Rsp += (UnwindCode.OpInfo + 1) * 8;
	    i++;
	    break;

	case UWOP_SET_FPREG:
	    Reg = UnwindInfo->FrameRegister;
	    Context->Rsp =
		GetReg(Context, Reg) - UnwindInfo->FrameOffset * 16;
	    i++;
	    break;

	case UWOP_SAVE_NONVOL:
	    Reg = UnwindCode.OpInfo;
	    Offset = *(USHORT *) (&UnwindInfo->UnwindCode[i + 1]);
	    SetRegFromStackValue(Context, ContextPointers, Reg,
				 (DWORD64 *) Context->Rsp + Offset);
	    i += 2;
	    break;

	case UWOP_SAVE_NONVOL_FAR:
	    Reg = UnwindCode.OpInfo;
	    Offset = *(ULONG *) (&UnwindInfo->UnwindCode[i + 1]);
	    SetRegFromStackValue(Context, ContextPointers, Reg,
				 (DWORD64 *) Context->Rsp + Offset);
	    i += 3;
	    break;

	case UWOP_EPILOG:
	    i += 1;
	    break;

	case UWOP_SPARE_CODE:
	    ASSERT(FALSE);
	    i += 2;
	    break;

	case UWOP_SAVE_XMM128:
	    Reg = UnwindCode.OpInfo;
	    Offset = *(USHORT *) (&UnwindInfo->UnwindCode[i + 1]);
	    SetXmmRegFromStackValue(Context, ContextPointers, Reg,
				    (M128A *) (Context->Rsp + Offset));
	    i += 2;
	    break;

	case UWOP_SAVE_XMM128_FAR:
	    Reg = UnwindCode.OpInfo;
	    Offset = *(ULONG *) (&UnwindInfo->UnwindCode[i + 1]);
	    SetXmmRegFromStackValue(Context, ContextPointers, Reg,
				    (M128A *) (Context->Rsp + Offset));
	    i += 3;
	    break;

	case UWOP_PUSH_MACHFRAME:
	    /* OpInfo is 1, when an error code was pushed, otherwise 0. */
	    Context->Rsp += UnwindCode.OpInfo * sizeof(DWORD64);

	    /* Now pop the MACHINE_FRAME (Yes, "magic numbers", deal with it) */
	    Context->Rip = *(PDWORD64) (Context->Rsp + 0x00);
	    Context->SegCs = *(PDWORD64) (Context->Rsp + 0x08);
	    Context->EFlags = *(PDWORD64) (Context->Rsp + 0x10);
	    Context->SegSs = *(PDWORD64) (Context->Rsp + 0x20);
	    Context->Rsp = *(PDWORD64) (Context->Rsp + 0x18);
	    ASSERT((i + 1) == UnwindInfo->CountOfCodes);
	    goto Exit;
	}
    }

    /* Check for chained info */
    if (UnwindInfo->Flags & UNW_FLAG_CHAININFO) {
	/* See https://docs.microsoft.com/en-us/cpp/build/exception-handling-x64?view=msvc-160#chained-unwind-info-structures */
	FunctionEntry =
	    (PRUNTIME_FUNCTION) & (UnwindInfo->
				   UnwindCode[(UnwindInfo->CountOfCodes +
					       1) & ~1]);
	UnwindInfo = RVA(ImageBase, FunctionEntry->UnwindData);
	i = 0;
	goto RepeatChainedInfo;
    }

    /* Unwind is finished, pop new Rip from Stack */
    if (Context->Rsp != 0) {
	Context->Rip = *(DWORD64 *) Context->Rsp;
	Context->Rsp += sizeof(DWORD64);
    }

Exit:
    /* Check if we have a handler and return it */
    if (UnwindInfo->Flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER)) {
	return RVA(ImageBase, *LanguageHandler);
    }

    return NULL;
}

/*!
  \remark The implementation is based on the description in this blog: http://www.nynaeve.net/?p=106

  Differences to the desciption:
  - Instead of using 2 pointers to the unwind context and previous context,
  that are being swapped and the context copied, the unwind context is
  kept in the local context and copied back into the context passed in
  by the caller.

  \see http://www.nynaeve.net/?p=106
*/
BOOLEAN RtlpUnwindInternal(IN OPTIONAL PVOID TargetFrame,
			   IN OPTIONAL PVOID TargetIp,
			   IN PEXCEPTION_RECORD ExceptionRecord,
			   IN PVOID ReturnValue,
			   IN PCONTEXT ContextRecord,
			   IN OPTIONAL PUNWIND_HISTORY_TABLE HistoryTable,
			   IN ULONG HandlerType)
{
    DISPATCHER_CONTEXT DispatcherContext;
    PEXCEPTION_ROUTINE ExceptionRoutine;
    EXCEPTION_DISPOSITION Disposition;
    PRUNTIME_FUNCTION FunctionEntry;
    ULONG_PTR StackLow, StackHigh;
    ULONG64 ImageBase, EstablisherFrame;
    CONTEXT UnwindContext;

    /* Get the current stack limits and registration frame */
    RtlpGetStackLimits(&StackLow, &StackHigh);

    /* If we have a target frame, then this is our high limit */
    if (TargetFrame != NULL) {
	StackHigh = (ULONG64) TargetFrame + 1;
    }

    /* Copy the context */
    UnwindContext = *ContextRecord;

    /* Set up the constant fields of the dispatcher context */
    DispatcherContext.ContextRecord = ContextRecord;
    DispatcherContext.HistoryTable = HistoryTable;
    DispatcherContext.TargetIp = (ULONG64) TargetIp;

    /* Start looping */
    while (TRUE) {
	/* Lookup the FunctionEntry for the current RIP */
	FunctionEntry = RtlLookupFunctionEntry(UnwindContext.Rip, &ImageBase, NULL);
	if (FunctionEntry == NULL) {
	    /* No function entry, so this must be a leaf function. Pop the return address from the stack.
	       Note: this can happen after the first frame as the result of an exception */
	    UnwindContext.Rip = *(DWORD64 *) UnwindContext.Rsp;
	    UnwindContext.Rsp += sizeof(DWORD64);
	    continue;
	}

	/* Do a virtual unwind to get the next frame */
	ExceptionRoutine = RtlVirtualUnwind(HandlerType,
					    ImageBase,
					    UnwindContext.Rip,
					    FunctionEntry,
					    &UnwindContext,
					    &DispatcherContext.HandlerData,
					    &EstablisherFrame, NULL);

	/* Check, if we are still within the stack boundaries */
	if ((EstablisherFrame < StackLow) || (EstablisherFrame >= StackHigh) || (EstablisherFrame & 7)) {
	    /// TODO: Handle DPC stack

	    /* If we are handling an exception, we are done here. */
	    if (HandlerType == UNW_FLAG_EHANDLER) {
		ExceptionRecord->ExceptionFlags |= EXCEPTION_STACK_INVALID;
		return FALSE;
	    }

	    __debugbreak();
	    RtlRaiseStatus(STATUS_BAD_STACK);
	}

	/* Check if we have an exception routine */
	if (ExceptionRoutine != NULL) {
	    /* Check if this is the target frame */
	    if (EstablisherFrame == (ULONG64) TargetFrame) {
		/* Set flag to inform the language handler */
		ExceptionRecord->ExceptionFlags |= EXCEPTION_TARGET_UNWIND;
	    }

	    /* Set up the variable fields of the dispatcher context */
	    DispatcherContext.ControlPc = ContextRecord->Rip;
	    DispatcherContext.ImageBase = ImageBase;
	    DispatcherContext.FunctionEntry = FunctionEntry;
	    DispatcherContext.LanguageHandler = ExceptionRoutine;
	    DispatcherContext.EstablisherFrame = EstablisherFrame;
	    DispatcherContext.ScopeIndex = 0;

	    /* Store the return value in the unwind context */
	    UnwindContext.Rax = (ULONG64) ReturnValue;

	    /* Loop all nested handlers */
	    do {
		/// TODO: call RtlpExecuteHandlerForUnwind instead
		/* Call the language specific handler */
		Disposition = ExceptionRoutine(ExceptionRecord,
					       (PVOID) EstablisherFrame,
					       &UnwindContext,
					       &DispatcherContext);

		/* Clear exception flags for the next iteration */
		ExceptionRecord->ExceptionFlags &= ~(EXCEPTION_TARGET_UNWIND | EXCEPTION_COLLIDED_UNWIND);

		/* Check if we do exception handling */
		if (HandlerType == UNW_FLAG_EHANDLER) {
		    if (Disposition == ExceptionContinueExecution) {
			/* Check if it was non-continuable */
			if (ExceptionRecord->ExceptionFlags & EXCEPTION_NONCONTINUABLE) {
			    __debugbreak();
			    RtlRaiseStatus
				(EXCEPTION_NONCONTINUABLE_EXCEPTION);
			}

			/* Execution continues */
			return TRUE;
		    } else if (Disposition == ExceptionNestedException) {
			/// TODO
			__debugbreak();
		    }
		}

		if (Disposition == ExceptionCollidedUnwind) {
		    /// TODO
		    __debugbreak();
		}

		/* This must be ExceptionContinueSearch now */
		if (Disposition != ExceptionContinueSearch) {
		    __debugbreak();
		    RtlRaiseStatus(STATUS_INVALID_DISPOSITION);
		}
	    } while (ExceptionRecord->ExceptionFlags & EXCEPTION_COLLIDED_UNWIND);
	}

	/* Check, if we have left our stack (8.) */
	if ((EstablisherFrame < StackLow) || (EstablisherFrame > StackHigh) || (EstablisherFrame & 7)) {
	    /// TODO: Check for DPC stack
	    __debugbreak();

	    if (UnwindContext.Rip == ContextRecord->Rip) {
		RtlRaiseStatus(STATUS_BAD_FUNCTION_TABLE);
	    } else {
		NtRaiseException(ExceptionRecord, ContextRecord, FALSE);
	    }
	}

	if (EstablisherFrame == (ULONG64) TargetFrame) {
	    break;
	}

	/* We have successfully unwound a frame. Copy the unwind context back. */
	*ContextRecord = UnwindContext;
    }

    if (ExceptionRecord->ExceptionCode != STATUS_UNWIND_CONSOLIDATE) {
	ContextRecord->Rip = (ULONG64) TargetIp;
    }

    /* Set the return value */
    ContextRecord->Rax = (ULONG64) ReturnValue;

    /* Restore the context */
    RtlRestoreContext(ContextRecord, ExceptionRecord);

    /* Should never get here! */
    ASSERT(FALSE);
    return FALSE;
}

NTAPI VOID RtlUnwindEx(IN OPTIONAL PVOID TargetFrame,
		       IN OPTIONAL PVOID TargetIp,
		       IN OPTIONAL PEXCEPTION_RECORD ExceptionRecord,
		       IN PVOID ReturnValue,
		       IN PCONTEXT ContextRecord,
		       IN OPTIONAL PUNWIND_HISTORY_TABLE HistoryTable)
{
    EXCEPTION_RECORD LocalExceptionRecord;

    /* Capture the current context */
    RtlCaptureContext(ContextRecord);

    /* Check if we have an exception record */
    if (ExceptionRecord == NULL) {
	/* No exception record was passed, so set up a local one */
	LocalExceptionRecord.ExceptionCode = STATUS_UNWIND;
	LocalExceptionRecord.ExceptionAddress = (PVOID) ContextRecord->Rip;
	LocalExceptionRecord.ExceptionRecord = NULL;
	LocalExceptionRecord.NumberParameters = 0;
	ExceptionRecord = &LocalExceptionRecord;
    }

    /* Call the internal function */
    RtlpUnwindInternal(TargetFrame, TargetIp, ExceptionRecord, ReturnValue,
		       ContextRecord, HistoryTable, UNW_FLAG_UHANDLER);
}

NTAPI VOID RtlUnwind(IN PVOID TargetFrame,
		     IN PVOID TargetIp,
		     IN PEXCEPTION_RECORD ExceptionRecord,
		     IN PVOID ReturnValue)
{
    UNIMPLEMENTED;
    return;
}

NTAPI ULONG RtlWalkFrameChain(OUT PVOID *Callers,
			      IN ULONG Count,
			      IN ULONG Flags)
{
    CONTEXT Context;
    ULONG64 ControlPc, ImageBase, EstablisherFrame;
    ULONG64 StackLow, StackHigh;
    PVOID HandlerData;
    ULONG i, FramesToSkip;
    PRUNTIME_FUNCTION FunctionEntry;

    DPRINT("Enter RtlWalkFrameChain\n");

    /* The upper bits in Flags define how many frames to skip */
    FramesToSkip = Flags >> 8;

    /* Capture the current Context */
    RtlCaptureContext(&Context);
    ControlPc = Context.Rip;

    /* Get the stack limits */
    RtlpGetStackLimits(&StackLow, &StackHigh);

    /* Check if we want the user-mode stack frame */
    if (Flags & 1) {
    }

    _SEH2_TRY {
	/* Loop the frames */
	for (i = 0; i < FramesToSkip + Count; i++) {
	    /* Lookup the FunctionEntry for the current ControlPc */
	    FunctionEntry =
		RtlLookupFunctionEntry(ControlPc, &ImageBase, NULL);

	    /* Is this a leaf function? */
	    if (!FunctionEntry) {
		Context.Rip = *(DWORD64 *) Context.Rsp;
		Context.Rsp += sizeof(DWORD64);
		DPRINT("leaf funtion, new Rip = %p, new Rsp = %p\n",
		       (PVOID) Context.Rip, (PVOID) Context.Rsp);
	    } else {
		RtlVirtualUnwind(UNW_FLAG_NHANDLER,
				 ImageBase,
				 ControlPc,
				 FunctionEntry,
				 &Context,
				 &HandlerData, &EstablisherFrame, NULL);
		DPRINT("normal funtion, new Rip = %p, new Rsp = %p\n",
		       (PVOID) Context.Rip, (PVOID) Context.Rsp);
	    }

	    /* Check if we left the user range */
	    if ((Context.Rip < 0x10000) || (Context.Rip > 0x000007FFFFFEFFFFULL)) {
		break;
	    }

	    /* Check, if we have left our stack */
	    if ((Context.Rsp < StackLow) || (Context.Rsp > StackHigh)) {
		break;
	    }

	    /* Continue with new Rip */
	    ControlPc = Context.Rip;

	    /* Save value, if we are past the frames to skip */
	    if (i >= FramesToSkip) {
		Callers[i - FramesToSkip] = (PVOID) ControlPc;
	    }
	}
    } _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER) {
	DPRINT1("Exception while getting callers!\n");
	i = 0;
    }
    _SEH2_END;

    DPRINT("RtlWalkFrameChain returns %d\n", i);
    return i;
}

/*! RtlGetCallersAddress
 * \ref http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/Debug/RtlGetCallersAddress.html
 */
#undef RtlGetCallersAddress
NTAPI VOID RtlGetCallersAddress(OUT PVOID *CallersAddress,
				OUT PVOID *CallersCaller)
{
    PVOID Callers[4];
    ULONG Number;

    /* Get callers:
     * RtlWalkFrameChain -> RtlGetCallersAddress -> x -> y */
    Number = RtlWalkFrameChain(Callers, 4, 0);

    *CallersAddress = (Number >= 3) ? Callers[2] : NULL;
    *CallersCaller = (Number == 4) ? Callers[3] : NULL;

    return;
}

static VOID RtlpCaptureNonVolatileContextPointers(OUT PKNONVOLATILE_CONTEXT_POINTERS NonvolatileContextPointers,
						  IN ULONG64 TargetFrame)
{
    CONTEXT Context;
    PRUNTIME_FUNCTION FunctionEntry;
    ULONG64 ImageBase;
    PVOID HandlerData;
    ULONG64 EstablisherFrame;

    /* Zero out the nonvolatile context pointers */
    RtlZeroMemory(NonvolatileContextPointers,
		  sizeof(*NonvolatileContextPointers));

    /* Capture the current context */
    RtlCaptureContext(&Context);

    do {
	/* Look up the function entry */
	FunctionEntry =
	    RtlLookupFunctionEntry(Context.Rip, &ImageBase, NULL);
	ASSERT(FunctionEntry != NULL);

	/* Do a virtual unwind to the caller and capture saved non-volatiles */
	RtlVirtualUnwind(UNW_FLAG_EHANDLER,
			 ImageBase,
			 Context.Rip,
			 FunctionEntry,
			 &Context,
			 &HandlerData,
			 &EstablisherFrame, NonvolatileContextPointers);

	/* Make sure nothing fishy is going on. Currently this is for kernel mode only. */
	ASSERT(EstablisherFrame != 0);
	ASSERT((LONG64) Context.Rip < 0);

	/* Continue until we reached the target frame or user mode */
    } while (EstablisherFrame < TargetFrame);

    /* If the caller did the right thing, we should get exactly the target frame */
    ASSERT(EstablisherFrame == TargetFrame);
}

VOID RtlSetUnwindContext(IN PCONTEXT Context, IN DWORD64 TargetFrame)
{
    KNONVOLATILE_CONTEXT_POINTERS ContextPointers;

    /* Capture pointers to the non-volatiles up to the target frame */
    RtlpCaptureNonVolatileContextPointers(&ContextPointers, TargetFrame);

    /* Copy the nonvolatiles to the captured locations */
    *ContextPointers.R12 = Context->R12;
    *ContextPointers.R13 = Context->R13;
    *ContextPointers.R14 = Context->R14;
    *ContextPointers.R15 = Context->R15;
    *ContextPointers.Xmm6 = Context->Xmm6;
    *ContextPointers.Xmm7 = Context->Xmm7;
    *ContextPointers.Xmm8 = Context->Xmm8;
    *ContextPointers.Xmm9 = Context->Xmm9;
    *ContextPointers.Xmm10 = Context->Xmm10;
    *ContextPointers.Xmm11 = Context->Xmm11;
    *ContextPointers.Xmm12 = Context->Xmm12;
    *ContextPointers.Xmm13 = Context->Xmm13;
    *ContextPointers.Xmm14 = Context->Xmm14;
    *ContextPointers.Xmm15 = Context->Xmm15;
}
