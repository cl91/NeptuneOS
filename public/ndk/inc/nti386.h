#pragma once

#define MAXIMUM_SUPPORTED_EXTENSION	512
#define SIZE_OF_80387_REGISTERS		80

typedef struct _FLOATING_SAVE_AREA {
  ULONG ControlWord;
  ULONG StatusWord;
  ULONG TagWord;
  ULONG ErrorOffset;
  ULONG ErrorSelector;
  ULONG DataOffset;
  ULONG DataSelector;
  UCHAR RegisterArea[SIZE_OF_80387_REGISTERS];
  ULONG Cr0NpxState;
} FLOATING_SAVE_AREA, *PFLOATING_SAVE_AREA;

#include "pshpack4.h"
typedef struct _CONTEXT {
  ULONG ContextFlags;
  ULONG Dr0;
  ULONG Dr1;
  ULONG Dr2;
  ULONG Dr3;
  ULONG Dr6;
  ULONG Dr7;
  FLOATING_SAVE_AREA FloatSave;
  ULONG SegGs;
  ULONG SegFs;
  ULONG SegEs;
  ULONG SegDs;
  ULONG Edi;
  ULONG Esi;
  ULONG Ebx;
  ULONG Edx;
  ULONG Ecx;
  ULONG Eax;
  ULONG Ebp;
  ULONG Eip;
  ULONG SegCs;
  ULONG EFlags;
  ULONG Esp;
  ULONG SegSs;
  UCHAR ExtendedRegisters[MAXIMUM_SUPPORTED_EXTENSION];
} CONTEXT, *PCONTEXT;
#include "poppack.h"
