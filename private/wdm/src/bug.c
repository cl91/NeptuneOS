/*
 * Bugcheck callback registration.
 */

#include "wdmp.h"

static LIST_ENTRY KiBugcheckCallbackListHead;
static BOOLEAN KiBugcheckInitialized;

static VOID KiInitializeBugcheck()
{
    if (!KiBugcheckInitialized) {
	InitializeListHead(&KiBugcheckCallbackListHead);
	IopInitializeDpcThread();
	KiBugcheckInitialized = TRUE;
    }
}

VOID KiNotifyBugcheck()
{
    PKUSER_SHARED_DATA Data = (PVOID)(ULONG_PTR)USER_SHARED_DATA;
    DPRINT("NTOS Bugchecked: %s\n", Data->BugcheckMsg);
    if (KiBugcheckInitialized) {
	LoopOverList(Record, &KiBugcheckCallbackListHead,
		     KBUGCHECK_CALLBACK_RECORD, Entry) {
	    Record->CallbackRoutine(Record->Buffer, Record->Length);
	}
    }
}

/*
 * @implemented
 */
NTAPI BOOLEAN KeRegisterBugCheckCallback(IN PKBUGCHECK_CALLBACK_RECORD CallbackRecord,
					 IN PKBUGCHECK_CALLBACK_ROUTINE CallbackRoutine,
					 IN PVOID Buffer,
					 IN ULONG Length,
					 IN PUCHAR Component)
{
    /* Check the Current State first so we don't double-register */
    if (CallbackRecord->State == BufferEmpty) {
	KiInitializeBugcheck();
        /* Set the Callback Settings and insert into the list */
        CallbackRecord->Length = Length;
        CallbackRecord->Buffer = Buffer;
        CallbackRecord->Component = Component;
        CallbackRecord->CallbackRoutine = CallbackRoutine;
        CallbackRecord->State = BufferInserted;
	if (IsListEmpty(&KiBugcheckCallbackListHead)) {
	    WdmRegisterBugcheckNotification();
	}
        InsertTailList(&KiBugcheckCallbackListHead, &CallbackRecord->Entry);
        return TRUE;
    }

    return FALSE;
}

/*
 * @implemented
 */
NTAPI BOOLEAN KeDeregisterBugCheckCallback(IN PKBUGCHECK_CALLBACK_RECORD CallbackRecord)
{
    if (CallbackRecord->State == BufferInserted) {
	assert(KiBugcheckInitialized);
        /* Reset state and remove from list */
        CallbackRecord->State = BufferEmpty;
        RemoveEntryList(&CallbackRecord->Entry);
	if (IsListEmpty(&KiBugcheckCallbackListHead)) {
	    WdmUnregisterBugcheckNotification();
	}
	return FALSE;
    }

    return FALSE;
}
