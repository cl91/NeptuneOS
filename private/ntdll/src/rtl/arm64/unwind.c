/*++

Copyright (c) 2025  Dr. Chang Liu, PhD.

Module Name:

    unwind.c

Abstract:

    ARM64-specific stack unwinding routines

Revision History:

    2025-01-10  File created

--*/

#include "../rtlp.h"

typedef struct _UNWIND_INFO_EXT {
    WORD Epilog;
    BYTE Codes;
    BYTE Reserved;
} UNWIND_INFO_EXT, *PUNWIND_INFO_EXT;

typedef struct _UNWIND_INFO_EPILOG {
    DWORD Offset : 18;
    DWORD Reserved : 4;
    DWORD Index : 10;
} UNWIND_INFO_EPILOG, *PUNWIND_INFO_EPILOG;

static const BYTE UNWIND_CODE_LEN[256] = {
    /* 00 */ 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
             1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    /* 20 */ 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
             1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    /* 40 */ 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
             1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    /* 60 */ 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
             1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    /* 80 */ 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
             1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    /* a0 */ 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
             1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    /* c0 */ 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
             2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    /* e0 */ 4, 1, 2, 1, 1, 1, 1, 3, 1, 1, 1, 1, 1, 1, 1, 1,
             1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1
};

static ULONG RtlpGetSequenceLen(IN BYTE *Ptr, IN BYTE *End)
{
    ULONG Ret = 0;

    while (Ptr < End) {
	if (*Ptr == 0xe4 || *Ptr == 0xe5)
	    break;
	if ((*Ptr & 0xf8) != 0xe8)
	    Ret++; /* custom stack frames don't count */
	Ptr += UNWIND_CODE_LEN[*Ptr];
    }
    return Ret;
}

static void RtlpRestoreRegs(IN LONG Reg,
			    IN LONG Count,
			    IN LONG Pos,
			    OUT PCONTEXT Context,
			    OUT OPTIONAL PKNONVOLATILE_CONTEXT_POINTERS CtxPtrs)
{
    LONG i, offset = max(0, Pos);
    for (i = 0; i < Count; i++) {
	if (CtxPtrs && Reg + i >= 19)
	    (&CtxPtrs->X19)[Reg + i - 19] = (DWORD64 *)Context->Sp + i + offset;
	Context->X[Reg + i] = ((DWORD64 *)Context->Sp)[i + offset];
    }
    if (Pos < 0)
	Context->Sp += -8 * Pos;
}

static void RtlpRestoreFpregs(IN LONG Reg,
			      IN LONG Count,
			      IN LONG Pos,
			      OUT PCONTEXT Context,
			      OUT OPTIONAL PKNONVOLATILE_CONTEXT_POINTERS CtxPtrs)
{
    LONG Offset = max(0, Pos);
    for (LONG i = 0; i < Count; i++) {
	if (CtxPtrs && Reg + i >= 8)
	    (&CtxPtrs->D8)[Reg + i - 8] = (DWORD64 *)Context->Sp + i + Offset;
	Context->V[Reg + i].D[0] = ((double *)Context->Sp)[i + Offset];
    }
    if (Pos < 0)
	Context->Sp += -8 * Pos;
}

static void RtlpRestoreQregs(IN LONG Reg,
			     IN LONG Count,
			     IN LONG Pos,
			     OUT PCONTEXT Context,
			     OUT OPTIONAL PKNONVOLATILE_CONTEXT_POINTERS CtxPtrs)
{
    LONG Offset = max(0, Pos);
    for (LONG i = 0; i < Count; i++) {
	if (CtxPtrs && Reg + i >= 8)
	    (&CtxPtrs->D8)[Reg + i - 8] = (DWORD64 *)Context->Sp + 2 * (i + Offset);
	Context->V[Reg + i].Low = ((DWORD64 *)Context->Sp)[2 * (i + Offset)];
	Context->V[Reg + i].High = ((DWORD64 *)Context->Sp)[2 * (i + Offset) + 1];
    }
    if (Pos < 0)
	Context->Sp += -16 * Pos;
}

static void RtlpRestoreAnyReg(IN LONG Reg,
			      IN LONG Count,
			      IN LONG Type,
			      IN LONG Pos,
			      OUT PCONTEXT context,
			      OUT OPTIONAL PKNONVOLATILE_CONTEXT_POINTERS ptrs)
{
    if (Reg & 0x20)
	Pos = -Pos - 1;

    switch (Type) {
    case 0:
	if (Count > 1 || Pos < 0)
	    Pos *= 2;
	RtlpRestoreRegs(Reg & 0x1f, Count, Pos, context, ptrs);
	break;
    case 1:
	if (Count > 1 || Pos < 0)
	    Pos *= 2;
	RtlpRestoreFpregs(Reg & 0x1f, Count, Pos, context, ptrs);
	break;
    case 2:
	RtlpRestoreQregs(Reg & 0x1f, Count, Pos, context, ptrs);
	break;
    }
}

static void RtlpDoPacAuth(IN OUT PCONTEXT Context)
{
    register DWORD64 X17 __asm__("x17") = Context->Lr;
    register DWORD64 X16 __asm__("x16") = Context->Sp;

    /* This is the autib1716 instruction. The hint instruction is used here
     * as gcc does not assemble autib1716 for pre armv8.3a targets. For
     * pre-armv8.3a targets, this is just treated as a hint instruction, which
     * is ignored. */
    __asm__("hint 0xe" : "+r"(X17) : "r"(X16));

    Context->Lr = X17;
}

static void RtlpProcessUnwindCodes(IN BYTE *Ptr,
				   IN BYTE *End,
				   OUT PCONTEXT Context,
				   OUT OPTIONAL PKNONVOLATILE_CONTEXT_POINTERS CtxPtrs,
				   LONG NumCodesToSkip,
				   BOOLEAN *FinalPcIsFromLr)
{
    ULONG Val, Len, SaveNext = 2;

    /* skip codes */
    while (Ptr < End && NumCodesToSkip) {
	if (*Ptr == 0xe4)
	    break;
	Ptr += UNWIND_CODE_LEN[*Ptr];
	NumCodesToSkip--;
    }

    while (Ptr < End) {
	if ((Len = UNWIND_CODE_LEN[*Ptr]) > 1) {
	    if (Ptr + Len > End)
		break;
	    Val = Ptr[0] * 0x100 + Ptr[1];
	} else
	    Val = *Ptr;

	if (*Ptr < 0x20) {
	    /* alloc_s */
	    Context->Sp += 16 * (Val & 0x1f);
	} else if (*Ptr < 0x40) {
	    /* save_r19r20_x */
	    RtlpRestoreRegs(19, SaveNext, -(Val & 0x1f), Context, CtxPtrs);
	} else if (*Ptr < 0x80) {
	    /* save_fplr */
	    RtlpRestoreRegs(29, 2, Val & 0x3f, Context, CtxPtrs);
	} else if (*Ptr < 0xc0) {
	    /* save_fplr_x */
	    RtlpRestoreRegs(29, 2, -(Val & 0x3f) - 1, Context, CtxPtrs);
	} else if (*Ptr < 0xc8) {
	    /* alloc_m */
	    Context->Sp += 16 * (Val & 0x7ff);
	} else if (*Ptr < 0xcc) {
	    /* save_regp */
	    RtlpRestoreRegs(19 + ((Val >> 6) & 0xf), SaveNext, Val & 0x3f, Context, CtxPtrs);
	} else if (*Ptr < 0xd0) {
	    /* save_regp_x */
	    RtlpRestoreRegs(19 + ((Val >> 6) & 0xf), SaveNext, -(Val & 0x3f) - 1, Context,
			 CtxPtrs);
	} else if (*Ptr < 0xd4) {
	    /* save_reg */
	    RtlpRestoreRegs(19 + ((Val >> 6) & 0xf), 1, Val & 0x3f, Context, CtxPtrs);
	} else if (*Ptr < 0xd6) {
	    /* save_reg_x */
	    RtlpRestoreRegs(19 + ((Val >> 5) & 0xf), 1, -(Val & 0x1f) - 1, Context, CtxPtrs);
	} else if (*Ptr < 0xd8) {
	    /* save_lrpair */
	    RtlpRestoreRegs(19 + 2 * ((Val >> 6) & 0x7), 1, Val & 0x3f, Context, CtxPtrs);
	    RtlpRestoreRegs(30, 1, (Val & 0x3f) + 1, Context, CtxPtrs);
	} else if (*Ptr < 0xda) {
	    /* save_fregp */
	    RtlpRestoreFpregs(8 + ((Val >> 6) & 0x7), SaveNext, Val & 0x3f, Context, CtxPtrs);
	} else if (*Ptr < 0xdc) {
	    /* save_fregp_x */
	    RtlpRestoreFpregs(8 + ((Val >> 6) & 0x7), SaveNext, -(Val & 0x3f) - 1, Context,
			   CtxPtrs);
	} else if (*Ptr < 0xde) {
	    /* save_freg */
	    RtlpRestoreFpregs(8 + ((Val >> 6) & 0x7), 1, Val & 0x3f, Context, CtxPtrs);
	} else if (*Ptr == 0xde) {
	    /* save_freg_x */
	    RtlpRestoreFpregs(8 + ((Val >> 5) & 0x7), 1, -(Val & 0x3f) - 1, Context, CtxPtrs);
	} else if (*Ptr == 0xe0) {
	    /* alloc_l */
	    Context->Sp += 16 * ((Ptr[1] << 16) + (Ptr[2] << 8) + Ptr[3]);
	} else if (*Ptr == 0xe1) {
	    /* set_fp */
	    Context->Sp = Context->Fp;
	} else if (*Ptr == 0xe2) {
	    /* add_fp */
	    Context->Sp = Context->Fp - 8 * (Val & 0xff);
	} else if (*Ptr == 0xe3) {
	    /* nop */
	} else if (*Ptr == 0xe4) {
	    /* end */
	    break;
	} else if (*Ptr == 0xe5) {
	    /* end_c, ignored */
	} else if (*Ptr == 0xe6) {
	    /* save_next */
	    SaveNext += 2;
	    Ptr += Len;
	    continue;
	} else if (*Ptr == 0xe7) {
	    /* save_any_reg */
	    RtlpRestoreAnyReg(Ptr[1], (Ptr[1] & 0x40) ? SaveNext : 1, Ptr[2] >> 6,
			    Ptr[2] & 0x3f, Context, CtxPtrs);
	} else if (*Ptr == 0xe9) {
	    /* MSFT_OP_MACHINE_FRAME */
	    Context->Pc = ((DWORD64 *)Context->Sp)[1];
	    Context->Sp = ((DWORD64 *)Context->Sp)[0];
	    Context->ContextFlags &= ~CONTEXT_UNWOUND_TO_CALL;
	    *FinalPcIsFromLr = FALSE;
	} else if (*Ptr == 0xea) {
	    /* MSFT_OP_CONTEXT */
	    DWORD flags = Context->ContextFlags & ~CONTEXT_UNWOUND_TO_CALL;
	    PCONTEXT src_ctx = (PCONTEXT)Context->Sp;
	    *Context = *src_ctx;
	    Context->ContextFlags = flags |
				    (src_ctx->ContextFlags & CONTEXT_UNWOUND_TO_CALL);
	    if (CtxPtrs) {
		for (ULONG i = 19; i < 29; i++)
		    (&CtxPtrs->X19)[i - 19] = &src_ctx->X[i];
		for (ULONG i = 8; i < 16; i++)
		    (&CtxPtrs->D8)[i - 8] = &src_ctx->V[i].Low;
	    }
	    *FinalPcIsFromLr = FALSE;
	} else if (*Ptr == 0xeb) {
	     /* MSFT_OP_EC_CONTEXT */
	    DPRINT("ARM64EC is not supported\n");
	    return;
	} else if (*Ptr == 0xec) {
	    /* MSFT_OP_CLEAR_UNWOUND_TO_CALL */
	    Context->Pc = Context->Lr;
	    Context->ContextFlags &= ~CONTEXT_UNWOUND_TO_CALL;
	    *FinalPcIsFromLr = FALSE;
	} else if (*Ptr == 0xfc) {
	    /* pac_sign_lr */
	    RtlpDoPacAuth(Context);
	} else {
	    DPRINT("unsupported code %02x\n", *Ptr);
	    return;
	}
	SaveNext = 2;
	Ptr += Len;
    }
}

static PVOID RtlpUnwindPackedData(IN ULONG_PTR ImageBase,
				  IN ULONG_PTR ControlPc,
				  IN PRUNTIME_FUNCTION FunctionEntry,
				  IN OUT PCONTEXT Context,
				  IN OUT OPTIONAL PKNONVOLATILE_CONTEXT_POINTERS CtxPtrs)
{
    ULONG Len, Offset, NumCodesToSkip = 0;
    ULONG IntSize = FunctionEntry->RegI * 8;
    ULONG FpSize = FunctionEntry->RegF * 8;
    ULONG HSize = FunctionEntry->H * 4;
    ULONG SavedRegSize, LocalSize;
    ULONG NumIntRegs, NumFpRegs, NumSavedRegs, NumLocalRegs;

    DPRINT("function %llx-%llx: len=%#x flag=%x regF=%u regI=%u H=%u CR=%u frame=%x\n",
	   ImageBase + FunctionEntry->BeginAddress,
	   ImageBase + FunctionEntry->BeginAddress + FunctionEntry->FunctionLength * 4,
	   FunctionEntry->FunctionLength, FunctionEntry->Flag, FunctionEntry->RegF,
	   FunctionEntry->RegI, FunctionEntry->H, FunctionEntry->CR, FunctionEntry->FrameSize);

    if (FunctionEntry->CR == 1)
	IntSize += 8;
    if (FunctionEntry->RegF)
	FpSize += 8;

    SavedRegSize = ((IntSize + FpSize + 8 * 8 * FunctionEntry->H) + 0xf) & ~0xf;
    LocalSize = FunctionEntry->FrameSize * 16 - SavedRegSize;

    NumIntRegs = IntSize / 8;
    NumFpRegs = FpSize / 8;
    NumSavedRegs = SavedRegSize / 8;
    NumLocalRegs = LocalSize / 8;

    /* check for prolog/epilog */
    if (FunctionEntry->Flag == 1) {
	Offset = ((ControlPc - ImageBase) - FunctionEntry->BeginAddress) / 4;
	if (Offset < 17 || Offset >= FunctionEntry->FunctionLength - 15) {
	    Len = (IntSize + 8) / 16 + (FpSize + 8) / 16;
	    switch (FunctionEntry->CR) {
	    case 2:
		Len++; /* pacibsp */
		/* fall through */
	    case 3:
		Len++; /* mov x29,sp */
		Len++; /* stp x29,lr,[sp,0] */
		if (LocalSize <= 512)
		    break;
		/* fall through */
	    case 0:
	    case 1:
		if (LocalSize)
		    Len++; /* sub sp,sp,#local_size */
		if (LocalSize > 4088)
		    Len++; /* sub sp,sp,#4088 */
		break;
	    }
	    if (Offset < Len + HSize) {
		/* prolog */
		NumCodesToSkip = Len + HSize - Offset;
	    } else if (Offset >= FunctionEntry->FunctionLength - (Len + 1)) {
		/* epilog */
		NumCodesToSkip = Offset - (FunctionEntry->FunctionLength - (Len + 1));
		HSize = 0;
	    }
	}
    }

    if (!NumCodesToSkip) {
	if (FunctionEntry->CR == 3 || FunctionEntry->CR == 2) {
	    /* mov x29,sp */
	    Context->Sp = Context->Fp;
	    RtlpRestoreRegs(29, 2, 0, Context, CtxPtrs);
	}
	Context->Sp += LocalSize;
	if (FpSize)
	    RtlpRestoreFpregs(8, NumFpRegs, NumIntRegs, Context, CtxPtrs);
	if (FunctionEntry->CR == 1)
	    RtlpRestoreRegs(30, 1, NumIntRegs - 1, Context, CtxPtrs);
	RtlpRestoreRegs(19, FunctionEntry->RegI, -NumSavedRegs, Context, CtxPtrs);
    } else {
	ULONG Pos = 0;

	switch (FunctionEntry->CR) {
	case 3:
	case 2:
	    /* mov x29,sp */
	    if (Pos++ >= NumCodesToSkip)
		Context->Sp = Context->Fp;
	    if (LocalSize <= 512) {
		/* stp x29,lr,[sp,-#local_size]! */
		if (Pos++ >= NumCodesToSkip)
		    RtlpRestoreRegs(29, 2, -NumLocalRegs, Context, CtxPtrs);
		break;
	    }
	    /* stp x29,lr,[sp,0] */
	    if (Pos++ >= NumCodesToSkip)
		RtlpRestoreRegs(29, 2, 0, Context, CtxPtrs);
	    /* fall through */
	case 0:
	case 1:
	    if (!LocalSize)
		break;
	    /* sub sp,sp,#local_size */
	    if (Pos++ >= NumCodesToSkip)
		Context->Sp += (LocalSize - 1) % 4088 + 1;
	    if (LocalSize > 4088 && Pos++ >= NumCodesToSkip)
		Context->Sp += 4088;
	    break;
	}

	Pos += HSize;

	if (FpSize) {
	    if (FunctionEntry->RegF % 2 == 0 && Pos++ >= NumCodesToSkip)
		/* str d%u,[sp,#fp_size] */
		RtlpRestoreFpregs(8 + FunctionEntry->RegF, 1,
				  NumIntRegs + NumFpRegs - 1, Context, CtxPtrs);
	    for (LONG i = (FunctionEntry->RegF + 1) / 2 - 1; i >= 0; i--) {
		if (Pos++ < NumCodesToSkip) {
		    continue;
		}
		if (!i && !IntSize) {
		    /* stp d8,d9,[sp,-#regsave]! */
		    RtlpRestoreFpregs(8, 2, -NumSavedRegs, Context, CtxPtrs);
		} else {
		    /* stp dn,dn+1,[sp,#offset] */
		    RtlpRestoreFpregs(8 + 2 * i, 2, NumIntRegs + 2 * i, Context, CtxPtrs);
		}
	    }
	}

	if (FunctionEntry->RegI % 2) {
	    if (Pos++ >= NumCodesToSkip) {
		/* stp xn,lr,[sp,#offset] */
		if (FunctionEntry->CR == 1) {
		    RtlpRestoreRegs(30, 1, NumIntRegs - 1, Context, CtxPtrs);
		}
		/* str xn,[sp,#offset] */
		RtlpRestoreRegs(18 + FunctionEntry->RegI, 1,
				(FunctionEntry->RegI > 1)?(FunctionEntry->RegI-1):(-NumSavedRegs),
				Context, CtxPtrs);
	    }
	} else if (FunctionEntry->CR == 1) {
	    /* str lr,[sp,#offset] */
	    if (Pos++ >= NumCodesToSkip) {
		RtlpRestoreRegs(30, 1,
				FunctionEntry->RegI ? (NumIntRegs - 1) : (-NumSavedRegs),
				Context, CtxPtrs);
	    }
	}

	for (LONG i = FunctionEntry->RegI / 2 - 1; i >= 0; i--) {
	    if (Pos++ < NumCodesToSkip) {
		continue;
	    }
	    if (i) {
		/* stp xn,xn+1,[sp,#offset] */
		RtlpRestoreRegs(19 + 2 * i, 2, 2 * i, Context, CtxPtrs);
	    } else {
		/* stp x19,x20,[sp,-#regsave]! */
		RtlpRestoreRegs(19, 2, -NumSavedRegs, Context, CtxPtrs);
	    }
	}
    }
    if (FunctionEntry->CR == 2)
	RtlpDoPacAuth(Context);
    return NULL;
}

static PVOID RtlpUnwindFullData(IN ULONG_PTR ImageBase,
				IN ULONG_PTR ControlPc,
				IN PRUNTIME_FUNCTION FunctionEntry,
				IN PCONTEXT Context,
				OUT PVOID *HandlerData,
				IN OUT OPTIONAL PKNONVOLATILE_CONTEXT_POINTERS CtxPtrs,
				OUT BOOLEAN *FinalPcIsFromLr)
{
    PRUNTIME_FUNCTION_XDATA UnwindData;
    PUNWIND_INFO_EPILOG InfoEpilog;
    ULONG Codes, Epilogs, Len, Offset;
    PVOID Data;
    BYTE *End;

    UnwindData = (PRUNTIME_FUNCTION_XDATA)((PCHAR)ImageBase + FunctionEntry->UnwindData);
    Data = UnwindData + 1;
    Epilogs = UnwindData->EpilogCount;
    Codes = UnwindData->CodeWords;
    if (!Codes && !Epilogs) {
	PUNWIND_INFO_EXT infoex = Data;
	Codes = infoex->Codes;
	Epilogs = infoex->Epilog;
	Data = infoex + 1;
    }
    InfoEpilog = Data;
    if (!UnwindData->EpilogInHeader)
	Data = InfoEpilog + Epilogs;

    Offset = ((ControlPc - ImageBase) - FunctionEntry->BeginAddress) / 4;
    End = (BYTE *)Data + Codes * 4;

    DPRINT("function %llx-%llx: len=%#x ver=%u X=%u E=%u epilogs=%u codes=%u\n",
	   ImageBase + FunctionEntry->BeginAddress,
	   ImageBase + FunctionEntry->BeginAddress + UnwindData->FunctionLength * 4,
	   UnwindData->FunctionLength, UnwindData->Version,
	   UnwindData->ExceptionDataPresent, UnwindData->EpilogInHeader,
	   Epilogs, Codes * 4);

    /* check for prolog */
    if (Offset < Codes * 4) {
	Len = RtlpGetSequenceLen(Data, End);
	if (Offset < Len) {
	    RtlpProcessUnwindCodes(Data, End, Context, CtxPtrs, Len - Offset,
				 FinalPcIsFromLr);
	    return NULL;
	}
    }

    /* check for epilog */
    if (!UnwindData->EpilogInHeader) {
	for (ULONG i = 0; i < Epilogs; i++) {
	    if (Offset < InfoEpilog[i].Offset)
		break;
	    if (Offset - InfoEpilog[i].Offset < Codes * 4 - InfoEpilog[i].Index) {
		BYTE *ptr = (BYTE *)Data + InfoEpilog[i].Index;
		Len = RtlpGetSequenceLen(ptr, End);
		if (Offset <= InfoEpilog[i].Offset + Len) {
		    RtlpProcessUnwindCodes(ptr, End, Context, CtxPtrs,
					 Offset - InfoEpilog[i].Offset,
					 FinalPcIsFromLr);
		    return NULL;
		}
	    }
	}
    } else if (UnwindData->FunctionLength - Offset <= Codes * 4 - Epilogs) {
	BYTE *Ptr = (BYTE *)Data + Epilogs;
	Len = RtlpGetSequenceLen(Ptr, End) + 1;
	if (Offset >= UnwindData->FunctionLength - Len) {
	    RtlpProcessUnwindCodes(Ptr, End, Context, CtxPtrs,
				 Offset - (UnwindData->FunctionLength - Len), FinalPcIsFromLr);
	    return NULL;
	}
    }

    RtlpProcessUnwindCodes(Data, End, Context, CtxPtrs, 0, FinalPcIsFromLr);

    /* get handler since we are inside the main code */
    if (UnwindData->ExceptionDataPresent) {
	DWORD *HandlerRva = (DWORD *)Data + Codes;
	*HandlerData = HandlerRva + 1;
	return (PCHAR)ImageBase + *HandlerRva;
    }
    return NULL;
}

PRUNTIME_FUNCTION RtlpLookupFunctionEntry(IN ULONG_PTR ControlPc,
					  IN ULONG_PTR ImageBase,
					  IN PRUNTIME_FUNCTION FunctionTable,
					  IN ULONG TableLength,
					  OUT OPTIONAL PUNWIND_HISTORY_TABLE HistoryTable)
{
    ULONG IndexLow = 0;
    ULONG IndexHigh = TableLength - 1;

    while (IndexLow <= IndexHigh) {
	ULONG IndexMid = (IndexLow + IndexHigh) / 2;
	ULONG_PTR FunctionStart = ImageBase + FunctionTable[IndexMid].BeginAddress;

	if (ControlPc >= FunctionStart) {
	    ULONG FunctionLength;
	    if (FunctionTable[IndexMid].Flag) {
		FunctionLength = FunctionTable[IndexMid].FunctionLength;
	    } else {
		PCHAR UnwindData = (PCHAR)ImageBase + FunctionTable[IndexMid].UnwindData;
		FunctionLength = ((PRUNTIME_FUNCTION_XDATA)UnwindData)->FunctionLength;
	    }
	    if (ControlPc < FunctionStart + 4 * FunctionLength)
		return FunctionTable + IndexMid;
	    IndexLow = IndexMid + 1;
	} else
	    IndexHigh = IndexMid - 1;
    }
    return NULL;
}

PEXCEPTION_ROUTINE RtlVirtualUnwind(IN ULONG HandlerType,
				    IN ULONG_PTR ImageBase,
				    IN ULONG_PTR ControlPc,
				    IN PRUNTIME_FUNCTION FunctionEntry,
				    IN OUT PCONTEXT Context,
				    OUT PVOID *HandlerData,
				    OUT PULONG_PTR EstablisherFrame,
				    IN OUT OPTIONAL PKNONVOLATILE_CONTEXT_POINTERS CtxPtrs)
{
    DPRINT("type %x base %llx pc %llx rva %llx sp %llx\n",
	   HandlerType, ImageBase, ControlPc, ControlPc - ImageBase, Context->Sp);

    if (!FunctionEntry && ControlPc == Context->Lr) {
	/* invalid leaf function */
	return NULL;
    }

    *HandlerData = NULL;
    Context->ContextFlags |= CONTEXT_UNWOUND_TO_CALL;

    PEXCEPTION_ROUTINE Handler;
    BOOLEAN FinalPcIsFromLr = TRUE;
    if (!FunctionEntry) {
	/* leaf function */
	Handler = NULL;
    } else if (FunctionEntry->Flag) {
	Handler = RtlpUnwindPackedData(ImageBase, ControlPc, FunctionEntry,
				     Context, CtxPtrs);
    } else {
	Handler = RtlpUnwindFullData(ImageBase, ControlPc, FunctionEntry, Context,
				     HandlerData, CtxPtrs, &FinalPcIsFromLr);
    }

    if (FinalPcIsFromLr)
	Context->Pc = Context->Lr;

    DPRINT("ret: pc=%llx lr=%llx sp=%llx handler=%p\n",
	   Context->Pc, Context->Lr, Context->Sp, *Handler);
    *EstablisherFrame = Context->Sp;
    return Handler;
}
