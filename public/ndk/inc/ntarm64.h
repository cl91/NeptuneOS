#pragma once

#define PAGE_SIZE 0x1000
#define PAGE_SHIFT 12L

#define YieldProcessor __yield

#define ARM64_MAX_BREAKPOINTS 8
#define ARM64_MAX_WATCHPOINTS 2

typedef union NEON128 {
    struct {
	ULONGLONG Low;
	LONGLONG High;
    };
    double D[2];
    float S[4];
    USHORT H[8];
    UCHAR B[16];
} NEON128, *PNEON128;

typedef struct DECLSPEC_ALIGN(16) _CONTEXT {
    //
    // Control flags.
    //
    ULONG ContextFlags;

    //
    // Integer registers
    //
    ULONG Cpsr;
    union {
	struct {
	    ULONG64 X0;
	    ULONG64 X1;
	    ULONG64 X2;
	    ULONG64 X3;
	    ULONG64 X4;
	    ULONG64 X5;
	    ULONG64 X6;
	    ULONG64 X7;
	    ULONG64 X8;
	    ULONG64 X9;
	    ULONG64 X10;
	    ULONG64 X11;
	    ULONG64 X12;
	    ULONG64 X13;
	    ULONG64 X14;
	    ULONG64 X15;
	    ULONG64 X16;
	    ULONG64 X17;
	    ULONG64 X18;
	    ULONG64 X19;
	    ULONG64 X20;
	    ULONG64 X21;
	    ULONG64 X22;
	    ULONG64 X23;
	    ULONG64 X24;
	    ULONG64 X25;
	    ULONG64 X26;
	    ULONG64 X27;
	    ULONG64 X28;
	    ULONG64 Fp;
	    ULONG64 Lr;
	};
	ULONG64 X[31];
    };

    ULONG64 Sp;
    ULONG64 Pc;

    //
    // Floating Point/NEON Registers
    //
    NEON128 V[32];
    ULONG Fpcr;
    ULONG Fpsr;

    //
    // Debug registers
    //
    ULONG Bcr[ARM64_MAX_BREAKPOINTS];
    ULONG64 Bvr[ARM64_MAX_BREAKPOINTS];
    ULONG Wcr[ARM64_MAX_WATCHPOINTS];
    ULONG64 Wvr[ARM64_MAX_WATCHPOINTS];
} CONTEXT, *PCONTEXT;

/* The following flags control the contents of the CONTEXT structure. */
#define CONTEXT_ARM64           0x400000UL
#define CONTEXT_CONTROL         (CONTEXT_ARM64 | 0x00000001UL)
#define CONTEXT_INTEGER         (CONTEXT_ARM64 | 0x00000002UL)
#define CONTEXT_FLOATING_POINT  (CONTEXT_ARM64 | 0x00000004UL)
#define CONTEXT_DEBUG_REGISTERS (CONTEXT_ARM64 | 0x00000008UL)
#define CONTEXT_ARM64_X18       (CONTEXT_ARM64 | 0x00000010UL)
#define CONTEXT_FULL		(CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_FLOATING_POINT)
#define CONTEXT_ALL		(CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS | CONTEXT_ARM64_X18)
#define CONTEXT_UNWOUND_TO_CALL 0x20000000UL

typedef struct _RUNTIME_FUNCTION {
    ULONG BeginAddress;
    union {
        ULONG UnwindData;
        struct {
            ULONG Flag : 2;
            ULONG FunctionLength : 11;
            ULONG RegF : 3;
            ULONG RegI : 4;
            ULONG H : 1;
            ULONG CR : 2;
            ULONG FrameSize : 9;
        };
    };
} RUNTIME_FUNCTION, *PRUNTIME_FUNCTION;

typedef union RUNTIME_FUNCTION_XDATA {
    ULONG HeaderData;
    struct {
        ULONG FunctionLength : 18;
        ULONG Version : 2;
        ULONG ExceptionDataPresent : 1;
        ULONG EpilogInHeader : 1;
        ULONG EpilogCount : 5;
        ULONG CodeWords : 5;
    };
} RUNTIME_FUNCTION_XDATA, *PRUNTIME_FUNCTION_XDATA;

typedef enum ARM64_FNPDATA_FLAGS {
    PdataRefToFullXdata = 0,
    PdataPackedUnwindFunction = 1,
    PdataPackedUnwindFragment = 2,
} ARM64_FNPDATA_FLAGS;

typedef enum ARM64_FNPDATA_CR {
    PdataCrUnchained = 0,
    PdataCrUnchainedSavedLr = 1,
    PdataCrChainedWithPac = 2,
    PdataCrChained = 3,
} ARM64_FNPDATA_CR;

typedef struct _KNONVOLATILE_CONTEXT_POINTERS {
    PULONG64 X19;
    PULONG64 X20;
    PULONG64 X21;
    PULONG64 X22;
    PULONG64 X23;
    PULONG64 X24;
    PULONG64 X25;
    PULONG64 X26;
    PULONG64 X27;
    PULONG64 X28;
    PULONG64 Fp;
    PULONG64 Lr;
    PULONG64 D8;
    PULONG64 D9;
    PULONG64 D10;
    PULONG64 D11;
    PULONG64 D12;
    PULONG64 D13;
    PULONG64 D14;
    PULONG64 D15;
} KNONVOLATILE_CONTEXT_POINTERS, *PKNONVOLATILE_CONTEXT_POINTERS;

#define NONVOL_INT_NUMREG_ARM64 11
#define NONVOL_FP_NUMREG_ARM64  8

#define NONVOL_INT_SIZE_ARM64 (NONVOL_INT_NUMREG_ARM64 * sizeof(ULONG64))
#define NONVOL_FP_SIZE_ARM64  (NONVOL_FP_NUMREG_ARM64 * sizeof(double))

typedef union _DISPATCHER_CONTEXT_NONVOLREG_ARM64 {
    BYTE Buffer[NONVOL_INT_SIZE_ARM64 + NONVOL_FP_SIZE_ARM64];
    struct {
        DWORD64 GpNvRegs[NONVOL_INT_NUMREG_ARM64];
        double  FpNvRegs[NONVOL_FP_NUMREG_ARM64];
    };
} DISPATCHER_CONTEXT_NONVOLREG_ARM64;

typedef struct __JUMP_BUFFER {
    unsigned __int64 Frame;
    unsigned __int64 Reserved;
    unsigned __int64 X19;
    unsigned __int64 X20;
    unsigned __int64 X21;
    unsigned __int64 X22;
    unsigned __int64 X23;
    unsigned __int64 X24;
    unsigned __int64 X25;
    unsigned __int64 X26;
    unsigned __int64 X27;
    unsigned __int64 X28;
    unsigned __int64 Fp;
    unsigned __int64 Lr;
    unsigned __int64 Sp;
    unsigned long Fpcr;
    unsigned long Fpsr;
    double D[8];
} _JUMP_BUFFER;
