#include <wdmp.h>
#include "coroutine.h"

PVOID KiCoroutineStackChainHead;
PVOID KiCurrentCoroutineStackTop;

/*
 * Returns the stack top of the first available coroutine stack.
 * Immediately before the stack top is the KI_COROUTINE_STACK structure.
 */
PVOID KiGetFirstAvailableCoroutineStack()
{
    PVOID StackTop = KiCoroutineStackChainHead;
    while (StackTop != NULL) {
	PKI_COROUTINE_STACK Stack = (PKI_COROUTINE_STACK)StackTop - 1;
	if (Stack->CurrentIrp == NULL) {
	    break;
	}
	StackTop = Stack->NextStackTop;
    }
    if (StackTop == NULL) {
	/* TODO: Ask server for more stacks */
	assert(FALSE);
	return NULL;
    }
    return StackTop;
}
