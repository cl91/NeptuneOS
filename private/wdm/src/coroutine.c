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
	if (Stack->CoroutineSavedSP == NULL) {
	    break;
	}
	StackTop = Stack->NextStackTop;
    }
    if (StackTop == NULL) {
	if (!NT_SUCCESS(IopCreateCoroutineStack(&StackTop))) {
	    /* System is out of memory. Not much can be done here. */
	    assert(FALSE);
	    return NULL;
	}
	assert(StackTop != NULL);
	PKI_COROUTINE_STACK Stack = (PKI_COROUTINE_STACK)StackTop - 1;
	Stack->NextStackTop = KiCoroutineStackChainHead;
	KiCoroutineStackChainHead = Stack;
	/* Just in case the server did not, clear the saved SP (seL4 always
	 * clears the page when allocating a new page, so this shouldn't
	 * happen, but we want to make sure there is no surprise). */
	Stack->CoroutineSavedSP = 0;
    }
    return StackTop;
}
