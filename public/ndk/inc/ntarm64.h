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

typedef struct _CONTEXT {
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
#define CONTEXT_ARM             0x200000L
#define CONTEXT_CONTROL         (CONTEXT_ARM | 0x00000001L)
#define CONTEXT_INTEGER         (CONTEXT_ARM | 0x00000002L)
#define CONTEXT_FLOATING_POINT  (CONTEXT_ARM | 0x00000004L)
#define CONTEXT_DEBUG_REGISTERS (CONTEXT_ARM | 0x00000008L)
#define CONTEXT_FULL            (CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_FLOATING_POINT)
