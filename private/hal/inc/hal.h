#pragma once

#include <nt.h>
#include <wdm.h>
#include <assert.h>
#include <halsvc.h>
#include <hal_halsvc_gen.h>

#define RET_ERR_EX(Expr, OnError)					\
    {NTSTATUS __tmp_rete = (Expr); if (!NT_SUCCESS(__tmp_rete)) {	\
	    DbgPrint("Expression %s in function %s @ %s:%d returned"	\
		     " error 0x%x\n",					\
		     #Expr, __func__, __FILE__, __LINE__, __tmp_rete);	\
	    {OnError;} return __tmp_rete; }}
#define RET_ERR(Expr)	RET_ERR_EX(Expr, {})

#define IopAllocatePoolEx(Ptr, Type, Size, OnError)		\
    Type *Ptr = (Type *) RtlAllocateHeap(RtlGetProcessHeap(),	\
					 HEAP_ZERO_MEMORY,	\
					 Size);			\
    if (Ptr == NULL) {						\
	OnError;						\
	return STATUS_NO_MEMORY;				\
    }

#define IopAllocatePool(Ptr, Type, Size)	\
    IopAllocatePoolEx(Ptr, Type, Size, {})

#define IopAllocateObjectEx(Ptr, Type)			\
    IopAllocatePoolEx(Ptr, Type, sizeof(Type), {})

#define IopAllocateObject(Ptr, Type)		\
    IopAllocateObjectEx(Ptr, Type, {})

#define IopFreePool(Ptr)			\
    RtlFreeHeap(RtlGetProcessHeap(), 0, Ptr)

/* irp.c */
extern PIO_REQUEST_PACKET IopIncomingIrpBuffer;
extern PIO_REQUEST_PACKET IopOutgoingIrpBuffer;
