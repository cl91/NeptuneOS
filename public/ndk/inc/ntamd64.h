#pragma once

#define PAGE_SIZE			0x1000
#define PAGE_SHIFT			12L

typedef XSAVE_FORMAT XMM_SAVE_AREA32, *PXMM_SAVE_AREA32;

typedef struct DECLSPEC_ALIGN(16) _CONTEXT {
    ULONG64 P1Home;
    ULONG64 P2Home;
    ULONG64 P3Home;
    ULONG64 P4Home;
    ULONG64 P5Home;
    ULONG64 P6Home;
    ULONG ContextFlags;
    ULONG MxCsr;
    USHORT SegCs;
    USHORT SegDs;
    USHORT SegEs;
    USHORT SegFs;
    USHORT SegGs;
    USHORT SegSs;
    ULONG EFlags;
    ULONG64 Dr0;
    ULONG64 Dr1;
    ULONG64 Dr2;
    ULONG64 Dr3;
    ULONG64 Dr6;
    ULONG64 Dr7;
    ULONG64 Rax;
    ULONG64 Rcx;
    ULONG64 Rdx;
    ULONG64 Rbx;
    ULONG64 Rsp;
    ULONG64 Rbp;
    ULONG64 Rsi;
    ULONG64 Rdi;
    ULONG64 R8;
    ULONG64 R9;
    ULONG64 R10;
    ULONG64 R11;
    ULONG64 R12;
    ULONG64 R13;
    ULONG64 R14;
    ULONG64 R15;
    ULONG64 Rip;
    union {
	XMM_SAVE_AREA32 FltSave;
	struct {
	    M128A Header[2];
	    M128A Legacy[8];
	    M128A Xmm0;
	    M128A Xmm1;
	    M128A Xmm2;
	    M128A Xmm3;
	    M128A Xmm4;
	    M128A Xmm5;
	    M128A Xmm6;
	    M128A Xmm7;
	    M128A Xmm8;
	    M128A Xmm9;
	    M128A Xmm10;
	    M128A Xmm11;
	    M128A Xmm12;
	    M128A Xmm13;
	    M128A Xmm14;
	    M128A Xmm15;
	};
    };
    M128A VectorRegister[26];
    ULONG64 VectorControl;
    ULONG64 DebugControl;
    ULONG64 LastBranchToRip;
    ULONG64 LastBranchFromRip;
    ULONG64 LastExceptionToRip;
    ULONG64 LastExceptionFromRip;
} CONTEXT, *PCONTEXT;

typedef struct _KNONVOLATILE_CONTEXT_POINTERS {
    union {
        PM128A FloatingContext[16];
        struct {
            PM128A Xmm0;
            PM128A Xmm1;
            PM128A Xmm2;
            PM128A Xmm3;
            PM128A Xmm4;
            PM128A Xmm5;
            PM128A Xmm6;
            PM128A Xmm7;
            PM128A Xmm8;
            PM128A Xmm9;
            PM128A Xmm10;
            PM128A Xmm11;
            PM128A Xmm12;
            PM128A Xmm13;
            PM128A Xmm14;
            PM128A Xmm15;
        };
    };

    union {
        PULONG64 IntegerContext[16];
        struct {
            PULONG64 Rax;
            PULONG64 Rcx;
            PULONG64 Rdx;
            PULONG64 Rbx;
            PULONG64 Rsp;
            PULONG64 Rbp;
            PULONG64 Rsi;
            PULONG64 Rdi;
            PULONG64 R8;
            PULONG64 R9;
            PULONG64 R10;
            PULONG64 R11;
            PULONG64 R12;
            PULONG64 R13;
            PULONG64 R14;
            PULONG64 R15;
        };
    };
} KNONVOLATILE_CONTEXT_POINTERS, *PKNONVOLATILE_CONTEXT_POINTERS;

struct _EXCEPTION_POINTERS;
typedef LONG (*PEXCEPTION_FILTER)(struct _EXCEPTION_POINTERS *ExceptionPointers,
				  PVOID EstablisherFrame);

typedef VOID (*PTERMINATION_HANDLER)(BOOLEAN AbnormalTermination,
				     PVOID EstablisherFrame);

#define UNW_FLAG_NHANDLER 0x0
#define UNW_FLAG_EHANDLER 0x1
#define UNW_FLAG_UHANDLER 0x2
#define UNW_FLAG_CHAININFO 0x4
#define UNW_FLAG_NO_EPILOGUE  0x80000000UL

#define RUNTIME_FUNCTION_INDIRECT 0x1

typedef struct _RUNTIME_FUNCTION {
    ULONG BeginAddress;
    ULONG EndAddress;
    ULONG UnwindData;
} RUNTIME_FUNCTION, *PRUNTIME_FUNCTION;

typedef PRUNTIME_FUNCTION GET_RUNTIME_FUNCTION_CALLBACK(IN DWORD64 ControlPc,
							IN OPTIONAL PVOID Context);
typedef GET_RUNTIME_FUNCTION_CALLBACK *PGET_RUNTIME_FUNCTION_CALLBACK;

#define UNWIND_HISTORY_TABLE_SIZE 12

typedef struct _UNWIND_HISTORY_TABLE_ENTRY {
    ULONG64 ImageBase;
    PRUNTIME_FUNCTION FunctionEntry;
} UNWIND_HISTORY_TABLE_ENTRY, *PUNWIND_HISTORY_TABLE_ENTRY;

#define UNWIND_HISTORY_TABLE_NONE 0
#define UNWIND_HISTORY_TABLE_GLOBAL 1
#define UNWIND_HISTORY_TABLE_LOCAL 2

typedef struct _UNWIND_HISTORY_TABLE {
    ULONG Count;
    BYTE  LocalHint;
    BYTE  GlobalHint;
    BYTE  Search;
    BYTE  Once;
    ULONG64 LowAddress;
    ULONG64 HighAddress;
    UNWIND_HISTORY_TABLE_ENTRY Entry[UNWIND_HISTORY_TABLE_SIZE];
} UNWIND_HISTORY_TABLE, *PUNWIND_HISTORY_TABLE;

typedef struct _DISPATCHER_CONTEXT {
    ULONG64 ControlPc;
    ULONG64 ImageBase;
    struct _RUNTIME_FUNCTION *FunctionEntry;
    ULONG64 EstablisherFrame;
    ULONG64 TargetIp;
    PCONTEXT ContextRecord;
    PEXCEPTION_ROUTINE LanguageHandler;
    PVOID HandlerData;
    struct _UNWIND_HISTORY_TABLE *HistoryTable;
    ULONG ScopeIndex;
    ULONG Fill0;
} DISPATCHER_CONTEXT, *PDISPATCHER_CONTEXT;

typedef struct _SCOPE_TABLE {
    ULONG Count;
    struct {
        ULONG BeginAddress;
        ULONG EndAddress;
        ULONG HandlerAddress;
        ULONG JumpTarget;
    } ScopeRecord[1];
} SCOPE_TABLE, *PSCOPE_TABLE;

#define CONTEXT_AMD64 0x100000

#define CONTEXT_CONTROL (CONTEXT_AMD64 | 0x1L)
#define CONTEXT_INTEGER (CONTEXT_AMD64 | 0x2L)
#define CONTEXT_SEGMENTS (CONTEXT_AMD64 | 0x4L)
#define CONTEXT_FLOATING_POINT (CONTEXT_AMD64 | 0x8L)
#define CONTEXT_DEBUG_REGISTERS (CONTEXT_AMD64 | 0x10L)

#define CONTEXT_FULL (CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_FLOATING_POINT)
#define CONTEXT_ALL (CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS)

#define CONTEXT_XSTATE (CONTEXT_AMD64 | 0x40L)

#define CONTEXT_EXCEPTION_ACTIVE 0x8000000
#define CONTEXT_SERVICE_ACTIVE 0x10000000
#define CONTEXT_EXCEPTION_REQUEST 0x40000000
#define CONTEXT_EXCEPTION_REPORTING 0x80000000

/*
 * EFlags
 */
#define EFLAGS_CF               0x01L
#define EFLAGS_ZF               0x40L
#define EFLAGS_TF               0x100L
#define EFLAGS_INTERRUPT_MASK   0x200L
#define EFLAGS_DF               0x400L
#define EFLAGS_IOPL             0x3000L
#define EFLAGS_NESTED_TASK      0x4000L
#define EFLAGS_RF               0x10000
#define EFLAGS_V86_MASK         0x20000
#define EFLAGS_ALIGN_CHECK      0x40000
#define EFLAGS_VIF              0x80000
#define EFLAGS_VIP              0x100000
#define EFLAGS_ID               0x200000
#define EFLAGS_USER_SANITIZE    0x3F4DD7
#define EFLAG_SIGN              0x8000
#define EFLAG_ZERO              0x4000
#define EFLAGS_TF_MASK          0x0100
#define EFLAGS_TF_SHIFT         0x0008
#define EFLAGS_ID_MASK          0x200000
#define EFLAGS_IF_MASK          0x0200
#define EFLAGS_IF_SHIFT         0x0009

#define YieldProcessor _mm_pause
