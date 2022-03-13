#pragma once

#include <ntos.h>
#include <ntimage.h>

#define PspAllocatePool(Var, Type)					\
    ExAllocatePoolEx(Var, Type, sizeof(Type), NTOS_PS_TAG, {})
#define PspAllocateArray(Var, Type, Size)				\
    ExAllocatePoolEx(Var, Type, sizeof(Type) * (Size), NTOS_PS_TAG, {})
#define PspAllocateArrayEx(Var, Type, Size, OnError)			\
    ExAllocatePoolEx(Var, Type, sizeof(Type) * (Size),			\
		     NTOS_PS_TAG, OnError)
#define PspFreePool(Var) ExFreePoolWithTag(Var, NTOS_PS_TAG)

/* Unsafe: no validation. Must be called after image file is fully mapped
 * into server address space and validated to be a PE image. */
static inline PIMAGE_NT_HEADERS PspImageNtHeader(IN PVOID FileBuffer)
{
    PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER) FileBuffer;
    return (PIMAGE_NT_HEADERS)((MWORD) FileBuffer + DosHeader->e_lfanew);
}

#define PROCESS_HEAP_DEFAULT_RESERVE	(64 * PAGE_SIZE)
#define PROCESS_HEAP_DEFAULT_COMMIT	(PAGE_SIZE)

/*
 * Creation context for the thread object creation routine
 */
typedef struct _THREAD_CREATION_CONTEXT {
    IN PPROCESS Process;
    IN PCONTEXT Context;
    IN PINITIAL_TEB InitialTeb;
    IN BOOLEAN CreateSuspended;
} THREAD_CREATION_CONTEXT, *PTHREAD_CREATION_CONTEXT;

/*
 * Creation context for the process object creation routine
 */
typedef struct _PROCESS_CREATION_CONTEXT {
    IN PIO_FILE_OBJECT ImageFile;
    IN PIO_DRIVER_OBJECT DriverObject;
    IN PSECTION ImageSection;
} PROCESS_CREATION_CONTEXT, *PPROCESS_CREATION_CONTEXT;

/* arch/context.c */
VOID PspInitializeThreadContext(IN PTHREAD Thread,
				IN PTHREAD_CONTEXT Context);
VOID PspInitializeSystemThreadContext(IN PSYSTEM_THREAD Thread,
				      IN PTHREAD_CONTEXT Context,
				      IN PSYSTEM_THREAD_ENTRY EntryPoint);

/* create.c */
NTSTATUS PspThreadObjectCreateProc(IN POBJECT Object,
				   IN PVOID CreaCtx);
NTSTATUS PspProcessObjectCreateProc(IN POBJECT Object,
				    IN PVOID CreaCtx);
VOID PspSystemThreadStartup(IN seL4_IPCBuffer *IpcBuffer,
			    IN PSYSTEM_THREAD_ENTRY EntryPoint);

/* init.c */
extern LIST_ENTRY PspProcessList;
extern PSECTION PspSystemDllSection;
extern PSUBSECTION PspSystemDllTlsSubsection;
extern PMMVAD PspUserSharedDataVad;
