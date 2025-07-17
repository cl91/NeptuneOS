#pragma once

#include <nt.h>
#include <sel4/sel4.h>
#include <pool.h>
#include "ke.h"
#include "mm.h"

#define EX_POOL_TAG(Tag0, Tag1, Tag2, Tag3)	((((Tag3) & 0x7fUL) << 24) \
						 | (((Tag2) & 0x7fUL) << 16) \
						 | (((Tag1) & 0x7fUL) << 8) \
						 | ((Tag0) & 0x7fUL))
#define EX_POOL_GET_TAG0(Tag)			((CHAR)(Tag & 0x7fUL))
#define EX_POOL_GET_TAG1(Tag)			((CHAR)(((Tag) >> 8) & 0x7fUL))
#define EX_POOL_GET_TAG2(Tag)			((CHAR)(((Tag) >> 16)& 0x7fUL))
#define EX_POOL_GET_TAG3(Tag)			((CHAR)(((Tag) >> 24) & 0x7fUL))

#define NTOS_EX_TAG				(EX_POOL_TAG('n','t','e','x'))

/*
 * Event object. This is the Executive object for KEVENT.
 */
typedef struct _EVENT_OBJECT {
    KEVENT Event;
    LIST_ENTRY Link;
} EVENT_OBJECT, *PEVENT_OBJECT;

/*
 * LPC port object.
 */
typedef struct _LPC_PORT_OBJECT {
    IPC_ENDPOINT Endpoint;
    LIST_ENTRY Link;
    AVL_TREE Connections;
    KEVENT ConnectionRequested;
    LIST_ENTRY QueuedConnections;
    ULONG MaxMessageLength;
} LPC_PORT_OBJECT, *PLPC_PORT_OBJECT;

typedef struct _LPC_PORT_CONNECTION {
    union {
	AVL_NODE Node;	    /* Key is thread id. */
	LIST_ENTRY Link;    /* List link for queued connection list */
    };
    PLPC_PORT_OBJECT PortObject;
    struct _THREAD *ClientThread;
    IPC_ENDPOINT ClientEndpoint;
    union {
	LIST_ENTRY ThreadLink;
	CLIENT_ID OldClientId;	/* Client ID of the dead client. */
    };
    KEVENT Connected;
    PEVENT_OBJECT EventObject;
    ULONG_PTR PortContext;
    PVOID ConnectionInformation;
    ULONG ConnectionInformationLength;
    BOOLEAN ConnectionInserted;	/* TRUE if the connection is inserted into the AVL tree. */
    BOOLEAN ConnectionRefused;
    BOOLEAN ClientDied;
} LPC_PORT_CONNECTION, *PLPC_PORT_CONNECTION;

/*
 * This can only be called in non-async functions
 */
#define ExAllocatePoolEx(Var, Type, Size, Tag, OnError)			\
    {} Type *Var = (Type *)ExAllocatePoolWithTag(Size, Tag);		\
    if ((Var) == NULL) {						\
	DbgPrint("Allocation of 0x%zx bytes for variable %s of type"	\
		 " (%s *) failed in function %s @ %s:%d\n",		\
		 (MWORD)Size, #Var, #Type,				\
		 __func__, __FILE__, __LINE__);				\
	{OnError;}							\
	COMPILE_CHECK_ASYNC_RETURN;					\
	return STATUS_NO_MEMORY;					\
    }

/*
 * This can only be called inside async functions
 */
#define ExAllocatePoolAsync(State, Var, Type, Size, Tag, OnError)	\
    {} Type *Var = (Type *)ExAllocatePoolWithTag(Size, Tag);		\
    if ((Var) == NULL) {						\
	DbgPrint("Allocation of 0x%zx bytes for variable %s of type"	\
		 " (%s *) failed in function %s @ %s:%d\n",		\
		 (MWORD) Size, #Var, #Type,				\
		 __func__, __FILE__, __LINE__);				\
	{OnError;}							\
	ASYNC_RETURN(State, STATUS_NO_MEMORY);				\
    }

/*
 * Creation context for the timer object creation routine
 */
typedef struct _TIMER_OBJ_CREATE_CONTEXT {
    TIMER_TYPE Type;
} TIMER_OBJ_CREATE_CONTEXT, *PTIMER_OBJ_CREATE_CONTEXT;


/* init.c */
NTSTATUS ExInitSystemPhase0(seL4_BootInfo *bootinfo);
NTSTATUS ExInitSystemPhase1();

/* pool.c */
NTSTATUS ExInitializePool(IN MWORD HeapStart, IN LONG NumPages);
PVOID ExAllocatePoolWithTag(IN MWORD NumberOfBytes, IN ULONG Tag);
VOID ExFreePoolWithTag(IN PCVOID Ptr, IN ULONG Tag);
BOOLEAN ExCheckPoolObjectTag(IN PCVOID Ptr, IN ULONG Tag);

/* lpc.c */
VOID ExClosePortConnection(IN PLPC_PORT_CONNECTION Connection,
			   IN BOOLEAN ThreadIsTerminating);
NTSTATUS ExCloseLocalHandle(IN struct _THREAD *Thread,
			    IN HANDLE Handle);
