/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS system libraries
 * PURPOSE:         Unwinding related functions
 * PROGRAMMER:      Timo Kreuzer (timo.kreuzer@reactos.org)
 */

/* INCLUDES *****************************************************************/

#include "../rtlp.h"

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

typedef union _UNWIND_CODE {
    struct {
	UCHAR CodeOffset;
	UCHAR UnwindOp : 4;
	UCHAR OpInfo : 4;
    };
    USHORT FrameOffset;
} UNWIND_CODE, *PUNWIND_CODE;

typedef struct _UNWIND_INFO {
    UCHAR Version : 3;
    UCHAR Flags : 5;
    UCHAR SizeOfProlog;
    UCHAR CountOfCodes;
    UCHAR FrameRegister : 4;
    UCHAR FrameOffset : 4;
    UNWIND_CODE UnwindCode[1];
/*    union {
      OPTIONAL ULONG ExceptionHandler;
      OPTIONAL ULONG FunctionEntry;
      };
      OPTIONAL ULONG ExceptionData[];
*/
} UNWIND_INFO, *PUNWIND_INFO;

/* FUNCTIONS *****************************************************************/

PRUNTIME_FUNCTION RtlpLookupFunctionEntry(IN ULONG64 ControlPc,
					  IN ULONG64 ImageBase,
					  IN PRUNTIME_FUNCTION FunctionTable,
					  IN ULONG TableLength,
					  OUT OPTIONAL PUNWIND_HISTORY_TABLE HistoryTable)
{
    /* Use relative virtual address */
    ControlPc -= ImageBase;

    /* Do a binary search */
    ULONG IndexLo = 0, IndexHi = TableLength;
    while (IndexHi > IndexLo) {
	ULONG IndexMid = (IndexLo + IndexHi) / 2;
	PRUNTIME_FUNCTION FunctionEntry = &FunctionTable[IndexMid];

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
			  IN ULONG64 Value)
{
    ((PULONG64)(&Context->Rax))[Reg] = Value;
}

static inline void SetRegFromStackValue(IN OUT PCONTEXT Context,
					IN OUT OPTIONAL PKNONVOLATILE_CONTEXT_POINTERS CtxPtrs,
					IN BYTE Reg,
					IN PULONG64 ValuePointer)
{
    SetReg(Context, Reg, *ValuePointer);
    if (CtxPtrs != NULL) {
	CtxPtrs->IntegerContext[Reg] = ValuePointer;
    }
}

static inline ULONG64 GetReg(IN PCONTEXT Context,
			     IN BYTE Reg)
{
    return ((PULONG64)(&Context->Rax))[Reg];
}

static inline void PopReg(IN OUT PCONTEXT Context,
			  IN OUT OPTIONAL PKNONVOLATILE_CONTEXT_POINTERS CtxPtrs,
			  IN BYTE Reg)
{
    SetRegFromStackValue(Context, CtxPtrs, Reg, (PULONG64)Context->Rsp);
    Context->Rsp += sizeof(ULONG64);
}

static inline void SetXmmReg(IN OUT PCONTEXT Context,
			     IN BYTE Reg,
			     IN M128A Value)
{
    ((M128A *) (&Context->Xmm0))[Reg] = Value;
}

static inline void SetXmmRegFromStackValue(OUT PCONTEXT Context,
					   IN OUT OPTIONAL PKNONVOLATILE_CONTEXT_POINTERS CtxPtrs,
					   IN BYTE Reg,
					   IN M128A *ValuePointer)
{
    SetXmmReg(Context, Reg, *ValuePointer);
    if (CtxPtrs != NULL) {
	CtxPtrs->FloatingContext[Reg] = ValuePointer;
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
static BOOLEAN RtlpTryToUnwindEpilog(IN OUT PCONTEXT Context,
				     IN ULONG64 ControlPc,
				     IN OUT OPTIONAL PKNONVOLATILE_CONTEXT_POINTERS CtxPtrs,
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

    InstrPtr = (BYTE *)ControlPc;

    /* Check if first instruction of epilog is "add rsp, x" */
    Instr = *(DWORD *)InstrPtr;
    if ((Instr & 0x00fffdff) == 0x00c48148) {
	if ((Instr & 0x0000ff00) == 0x8300) {
	    /* This is "add rsp, 0x??" */
	    LocalContext.Rsp += Instr >> 24;
	    InstrPtr += 4;
	} else {
	    /* This is "add rsp, 0x???????? */
	    LocalContext.Rsp += *(DWORD *)(InstrPtr + 3);
	    InstrPtr += 7;
	}
    } else if ((Instr & 0x38fffe) == 0x208d48) {
	/* Check if first instruction of epilog is "lea rsp, ...".
	 * Get the register first. */
	Reg = (Instr >> 16) & 0x7;

	/* REX.R */
	Reg += (Instr & 1) * 8;
	LocalContext.Rsp = GetReg(&LocalContext, Reg);

	/* Get adressing mode */
	Mod = (Instr >> 22) & 0x3;
	if (Mod == 0) {
	    /* No displacement */
	    InstrPtr += 3;
	} else if (Mod == 1) {
	    /* 1 byte displacement */
	    LocalContext.Rsp += (LONG)(CHAR)(Instr >> 24);
	    InstrPtr += 4;
	} else if (Mod == 2) {
	    /* 4 bytes displacement */
	    LocalContext.Rsp += *(LONG *)(InstrPtr + 3);
	    InstrPtr += 7;
	}
    }

    /* Loop the following instructions before the ret */
    EndAddress = FunctionEntry->EndAddress + ImageBase - 1;
    while ((ULONG64)InstrPtr < EndAddress) {
	Instr = *(DWORD *) InstrPtr;

	/* Check for a simple pop */
	if ((Instr & 0xf8) == 0x58) {
	    /* Opcode pops a basic register from stack */
	    Reg = Instr & 0x7;
	    PopReg(&LocalContext, CtxPtrs, Reg);
	    InstrPtr++;
	    continue;
	}

	/* Check for REX + pop */
	if ((Instr & 0xf8fb) == 0x5841) {
	    /* Opcode is pop r8 .. r15 */
	    Reg = ((Instr >> 8) & 0x7) + 8;
	    PopReg(&LocalContext, CtxPtrs, Reg);
	    InstrPtr += 2;
	    continue;
	}

	/* Opcode not allowed for Epilog */
	return FALSE;
    }

    // check for popfq

    // also allow end with jmp imm, jmp [target], iretq

    /* Check if we are at the ret instruction */
    if ((ULONG64)InstrPtr != EndAddress) {
	/* If we went past the end of the function, something is broken! */
	ASSERT((ULONG64)InstrPtr <= EndAddress);
	return FALSE;
    }

    /* Make sure this is really a ret instruction. Clang may generate int 3 (0xcc)
     * instead of a ret instruction after a call to RtlRaiseStatus so this may not
     * always be true.*/
    if (*InstrPtr != 0xc3) {
	return FALSE;
    }

    /* Unwind is finished, pop new Rip from Stack */
    LocalContext.Rip = *(PULONG64)LocalContext.Rsp;
    LocalContext.Rsp += sizeof(ULONG64);

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
    /* Check if we have a frame register */
    if (UnwindInfo->FrameRegister == 0) {
	/* No frame register means we use Rsp */
	return Context->Rsp;
    }

    if ((CodeOffset >= UnwindInfo->SizeOfProlog) || (UnwindInfo->Flags & UNW_FLAG_CHAININFO)) {
	return GetReg(Context, UnwindInfo->FrameRegister) - UnwindInfo->FrameOffset * 16;
    }

    /* Loop all unwind ops */
    for (ULONG i = 0; i < UnwindInfo->CountOfCodes; i += UnwindOpSlots(UnwindInfo->UnwindCode[i])) {
	/* Skip codes past our code offset */
	if (UnwindInfo->UnwindCode[i].CodeOffset > CodeOffset) {
	    continue;
	}

	/* Check for SET_FPREG */
	if (UnwindInfo->UnwindCode[i].UnwindOp == UWOP_SET_FPREG) {
	    return GetReg(Context, UnwindInfo->FrameRegister) - UnwindInfo->FrameOffset * 16;
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
					  IN OUT OPTIONAL PKNONVOLATILE_CONTEXT_POINTERS CtxPtrs)
{
    DbgTrace("HandlerType %d ImageBase %p ControlPc %p FunctionEntry %p. Context is\n",
	     HandlerType, (PVOID)ImageBase, (PVOID)ControlPc, FunctionEntry);
    RtlpDumpContext(Context);

    /* Get relative virtual address */
    ULONG_PTR ControlRva = ControlPc - ImageBase;

    /* Sanity checks */
    if ((ControlRva < FunctionEntry->BeginAddress) || (ControlRva >= FunctionEntry->EndAddress)) {
	return NULL;
    }

    /* Get a pointer to the unwind info */
    PUNWIND_INFO UnwindInfo = RVA(ImageBase, FunctionEntry->UnwindData);
    DbgTrace("UnwindInfo %p\n", UnwindInfo);

    /* The language specific handler data follows the unwind info */
    PULONG LanguageHandler = ALIGN_UP_POINTER_BY(&UnwindInfo->UnwindCode[UnwindInfo->CountOfCodes],
						 sizeof(ULONG));

    /* Calculate relative offset to function start */
    ULONG_PTR CodeOffset = ControlRva - FunctionEntry->BeginAddress;

    *EstablisherFrame = GetEstablisherFrame(Context, UnwindInfo, CodeOffset);

    /* Check if we are in the function epilog and try to finish it */
    if ((CodeOffset > UnwindInfo->SizeOfProlog) && (UnwindInfo->CountOfCodes > 0)) {
	if (RtlpTryToUnwindEpilog(Context, ControlPc, CtxPtrs, ImageBase, FunctionEntry)) {
	    /* There's no exception routine */
	    return NULL;
	}
    }

    /* Skip all Ops with an offset greater than the current Offset */
    ULONG i = 0;
    while ((i < UnwindInfo->CountOfCodes) && (UnwindInfo->UnwindCode[i].CodeOffset > CodeOffset)) {
	i += UnwindOpSlots(UnwindInfo->UnwindCode[i]);
    }

RepeatChainedInfo:
    /* Process the remaining unwind ops */
    while (i < UnwindInfo->CountOfCodes) {
	ULONG Offset;
	UNWIND_CODE UnwindCode;
	BYTE Reg;
	UnwindCode = UnwindInfo->UnwindCode[i];
	switch (UnwindCode.UnwindOp) {
	case UWOP_PUSH_NONVOL:
	    Reg = UnwindCode.OpInfo;
	    PopReg(Context, CtxPtrs, Reg);
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
	    Context->Rsp = GetReg(Context, Reg) - UnwindInfo->FrameOffset * 16;
	    i++;
	    break;

	case UWOP_SAVE_NONVOL:
	    Reg = UnwindCode.OpInfo;
	    Offset = UnwindInfo->UnwindCode[i + 1].FrameOffset;
	    SetRegFromStackValue(Context, CtxPtrs, Reg,
				 (PULONG64)Context->Rsp + Offset);
	    i += 2;
	    break;

	case UWOP_SAVE_NONVOL_FAR:
	    Reg = UnwindCode.OpInfo;
	    Offset = *(ULONG *)(&UnwindInfo->UnwindCode[i + 1]);
	    SetRegFromStackValue(Context, CtxPtrs, Reg,
				 (PULONG64)Context->Rsp + Offset);
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
	    Offset = UnwindInfo->UnwindCode[i + 1].FrameOffset;
	    SetXmmRegFromStackValue(Context, CtxPtrs, Reg,
				    (M128A*)Context->Rsp + Offset);
	    i += 2;
	    break;

	case UWOP_SAVE_XMM128_FAR:
	    Reg = UnwindCode.OpInfo;
	    Offset = *(ULONG *)(&UnwindInfo->UnwindCode[i + 1]);
	    SetXmmRegFromStackValue(Context, CtxPtrs, Reg,
				    (M128A *)Context->Rsp + Offset);
	    i += 3;
	    break;

	case UWOP_PUSH_MACHFRAME:
	    DbgTrace("UWOP_PUSH_MACHFRAME  Old RSP %p  NumberOfErrorCode %d\n",
		     (PVOID)Context->Rsp, UnwindCode.OpInfo);
	    /* OpInfo is 1, when an error code was pushed, otherwise 0. */
	    Context->Rsp += UnwindCode.OpInfo * sizeof(ULONG64);

	    /* Now pop the MACHINE_FRAME (RIP/RSP only. Yes, "magic numbers", deal with it) */
	    Context->Rip = *(PULONG64)(Context->Rsp + 0x00);
	    Context->Rsp = *(PULONG64)(Context->Rsp + 0x18);
	    DbgTrace("New RIP %p EFlags 0x%x RSP %p\n",
		     (PVOID)Context->Rip, Context->EFlags, (PVOID)Context->Rsp);
	    ASSERT((i + 1) == UnwindInfo->CountOfCodes);
	    goto Exit;
	}
    }

    /* Check for chained info */
    if (UnwindInfo->Flags & UNW_FLAG_CHAININFO) {
	/* See https://docs.microsoft.com/en-us/cpp/build/exception-handling-x64?view=msvc-160#chained-unwind-info-structures */
	FunctionEntry = (PRUNTIME_FUNCTION)&UnwindInfo->UnwindCode[(UnwindInfo->CountOfCodes + 1) & ~1];
	UnwindInfo = RVA(ImageBase, FunctionEntry->UnwindData);
	i = 0;
	goto RepeatChainedInfo;
    }

    /* Unwind is finished, pop new Rip from Stack */
    if (Context->Rsp != 0) {
	Context->Rip = *(PULONG64)Context->Rsp;
	Context->Rsp += sizeof(ULONG64);
    }

Exit:
    /* Check if we have a handler and return it */
    if (UnwindInfo->Flags & (HandlerType & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER))) {
	*HandlerData = LanguageHandler + 1;
	return RVA(ImageBase, *LanguageHandler);
    }

    return NULL;
}

static VOID
RtlpCaptureNonVolatileContextPointers(OUT PKNONVOLATILE_CONTEXT_POINTERS NvCtxPtr,
				      IN ULONG64 TargetFrame)
{
    CONTEXT Context;
    PRUNTIME_FUNCTION FunctionEntry;
    ULONG64 ImageBase;
    PVOID HandlerData;
    ULONG64 EstablisherFrame;

    /* Zero out the nonvolatile context pointers */
    RtlZeroMemory(NvCtxPtr, sizeof(*NvCtxPtr));

    /* Capture the current context */
    RtlCaptureContext(&Context);

    do {
	/* Look up the function entry */
	FunctionEntry = RtlLookupFunctionEntry(Context.Rip, &ImageBase, NULL);
	ASSERT(FunctionEntry != NULL);

	/* Do a virtual unwind to the caller and capture saved non-volatiles */
	RtlVirtualUnwind(UNW_FLAG_EHANDLER,
			 ImageBase,
			 Context.Rip,
			 FunctionEntry,
			 &Context,
			 &HandlerData,
			 &EstablisherFrame, NvCtxPtr);

	/* Make sure nothing fishy is going on. */
	ASSERT(EstablisherFrame != 0);
	ASSERT((LONG64)Context.Rip < 0);

	/* Continue until we reached the target frame or user mode */
    } while (EstablisherFrame < TargetFrame);

    /* If the caller did the right thing, we should get exactly the target frame */
    ASSERT(EstablisherFrame == TargetFrame);
}

NTAPI VOID RtlSetUnwindContext(IN PCONTEXT Context,
			       IN ULONG64 TargetFrame)
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
