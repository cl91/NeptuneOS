#include "../psp.h"

VOID PspInitializeThreadContext(IN PTHREAD Thread,
				IN PTHREAD_CONTEXT Context)
{
    assert(Thread != NULL);
    assert(Thread->Process != NULL);
    assert(Thread->IpcBufferClientPage != NULL);
    assert(Thread->TEBClientAddr);
    assert(Thread->StackTop);
    assert(Context != NULL);
    Context->eax = Thread->IpcBufferClientPage->AvlNode.Key;
    Context->eip = (MWORD) Thread->Process->ImageSection->
	ImageSectionObject->ImageInformation.TransferAddress;
    Context->esp = Thread->StackTop;
    Context->ebp = Thread->StackTop;
    Context->fs_base = Thread->TEBClientAddr;
}
