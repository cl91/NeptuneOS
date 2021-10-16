#pragma once

#include <nt.h>
#include <ntos.h>
#include <sel4/sel4.h>

#define KiAllocatePoolEx(Var, Type, OnError)				\
    ExAllocatePoolEx(Var, Type, sizeof(Type), NTOS_KE_TAG, OnError)
#define KiAllocatePool(Var, Type)	KiAllocatePoolEx(Var, Type, {})
#define KiAllocateArray(Var, Type, Size, OnError)			\
    ExAllocatePoolEx(Var, Type, sizeof(Type) * (Size), NTOS_KE_TAG, OnError)

/* bugcheck.c */
VOID KiHaltSystem(IN PCSTR Format, ...);

#define HALT_IF_ERR(Expr)	{NTSTATUS Error = (Expr); if (!NT_SUCCESS(Error)) { \
	    KiHaltSystem("Unrecoverable error at %s @ %s line %d: Error Code 0x%x. System halted.\n", \
			 __func__, __FILE__, __LINE__, Error);}}

/* vga.c */
VOID KiInitVga();

/* services.c */
NTSTATUS KiCreateExecutiveServicesEndpoint();
VOID KiDispatchExecutiveServices();
