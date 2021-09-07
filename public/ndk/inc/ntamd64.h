#pragma once

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
    } DUMMYSTRUCTNAME;
  } DUMMYUNIONNAME;
  M128A VectorRegister[26];
  ULONG64 VectorControl;
  ULONG64 DebugControl;
  ULONG64 LastBranchToRip;
  ULONG64 LastBranchFromRip;
  ULONG64 LastExceptionToRip;
  ULONG64 LastExceptionFromRip;
} CONTEXT, *PCONTEXT;

struct _EXCEPTION_POINTERS;
typedef LONG (*PEXCEPTION_FILTER)(struct _EXCEPTION_POINTERS *ExceptionPointers,
				  PVOID EstablisherFrame);

typedef VOID (*PTERMINATION_HANDLER)(BOOLEAN AbnormalTermination,
				     PVOID EstablisherFrame);

typedef struct _RUNTIME_FUNCTION {
    ULONG BeginAddress;
    ULONG EndAddress;
    ULONG UnwindData;
} RUNTIME_FUNCTION, *PRUNTIME_FUNCTION;

#define UNWIND_HISTORY_TABLE_SIZE 12

typedef struct _UNWIND_HISTORY_TABLE_ENTRY {
    ULONG64 ImageBase;
    PRUNTIME_FUNCTION FunctionEntry;
} UNWIND_HISTORY_TABLE_ENTRY, *PUNWIND_HISTORY_TABLE_ENTRY;

#define UNWIND_HISTORY_TABLE_NONE 0
#define UNWIND_HISTORY_TABLE_GLOBAL 1
#define UNWIND_HISTORY_TABLE_LOCAL 2

typedef struct _UNWIND_HISTORY_TABLE
{
    ULONG Count;
    BYTE  LocalHint;
    BYTE  GlobalHint;
    BYTE  Search;
    BYTE  Once;
    ULONG64 LowAddress;
    ULONG64 HighAddress;
    UNWIND_HISTORY_TABLE_ENTRY Entry[UNWIND_HISTORY_TABLE_SIZE];
} UNWIND_HISTORY_TABLE, *PUNWIND_HISTORY_TABLE;

typedef struct _DISPATCHER_CONTEXT
{
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
    struct
    {
        ULONG BeginAddress;
        ULONG EndAddress;
        ULONG HandlerAddress;
        ULONG JumpTarget;
    } ScopeRecord[1];
} SCOPE_TABLE, *PSCOPE_TABLE;
