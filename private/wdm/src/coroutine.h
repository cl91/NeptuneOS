#pragma once

/*
 * This is placed at the top of the coroutine stack. The top of the
 * stack is a pointer to the stack top of the next coroutine stack.
 *
 * Note: Stack grows in the direction of lower address.
 *
 * Schematics of the stack organization: (assuming i386, stack size
 * is one page and stack top is at 0x1000)
 *
 *   0xfe0                    0xff0             0xff4           0xff8        0xffc          0x1000
 *   |--------------------------------------------------------------------------------------|
 *   | Callee-saved registers | OldStackPointer | ReturnAddress | CurrentIrp | NextStackTop |
 *   |--------------------------------------------------------------------------------------|
 *                                                                                          ^
 *                                                                                          StackTop
 *
 * IMPORTANT: If you change this you must change arch/coroutine.S
 */
typedef struct _KI_COROUTINE_STACK {
    PVOID OldStackPointer; /* The old esp/rsp at the time KI_INVOKE_COROUTINE is called */
    PVOID ReturnAddress; /* Address that KiCoroutineYield() will jump to */
    PIRP_QUEUE_ENTRY CurrentIrp; /* Current IRP queue entry being processed */
    PVOID NextStackTop; /* Pointer to the next coroutine stack. */
} KI_COROUTINE_STACK, *PKI_COROUTINE_STACK;

/*
 * Coroutine entry point. This is called by IopStartCoroutine
 *
 * Irp is passed via %ecx (i386) or %rcx (amd64)
 */
typedef NTSTATUS (FASTCALL KI_COROUTINE_ENTRYPOINT)(IN PIRP_QUEUE_ENTRY Irp);

/* coroutine.c */
extern PVOID KiCoroutineStackChainHead;
extern PVOID KiCurrentCoroutineStackTop;
PVOID KiGetFirstAvailableCoroutineStack();

/* arch/coroutine.S */
FASTCALL NTSTATUS IopStartCoroutine(IN PVOID StackTop,
				    IN PIRP_QUEUE_ENTRY Entry);

/* irp.c */
KI_COROUTINE_ENTRYPOINT IopCallDispatchRoutine;
