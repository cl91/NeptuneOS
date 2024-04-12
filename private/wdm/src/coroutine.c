#include <wdmp.h>

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
	if (!NT_SUCCESS(WdmCreateCoroutineStack(&StackTop))) {
	    /* System is out of memory. Not much can be done here. */
	    assert(FALSE);
	    return NULL;
	}
	assert(StackTop != NULL);
	PKI_COROUTINE_STACK Stack = (PKI_COROUTINE_STACK)StackTop - 1;
	Stack->NextStackTop = KiCoroutineStackChainHead;
	KiCoroutineStackChainHead = StackTop;
	/* Just in case the server did not, clear the saved SP (seL4 always
	 * clears the page when allocating a new page, so this shouldn't
	 * happen, but we want to make sure there is no surprise). */
	assert(Stack->CoroutineSavedSP == 0);
	Stack->CoroutineSavedSP = 0;
    }
    return StackTop;
}

VOID KiDbgDumpCoroutineStacks()
{
    DbgTrace("Dumping coroutine stack chain head %p\n",
	     KiCoroutineStackChainHead);
    PKI_COROUTINE_STACK StackTop = KiCoroutineStackChainHead;
    while (StackTop != NULL) {
	DbgPrint("  (ST %p, SP %p)", StackTop, StackTop[-1].CoroutineSavedSP);
	StackTop = StackTop[-1].NextStackTop;
    }
    DbgPrint("\n");
}
