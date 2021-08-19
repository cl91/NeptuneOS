#include "../psp.h"

VOID PspInitializeThreadContext(IN PTHREAD Thread,
				IN PTHREAD_CONTEXT Context)
{
    assert(Thread != NULL);
    assert(Thread->Process != NULL);
    assert(Thread->IpcBufferClientPage != NULL);
    assert(Thread->TEBClientAddr);
    assert(Thread->StackTop);
    Context.rax = Thread->IpcBufferClientPage->AvlNode.Key;
    Context.rip = (MWORD) Thread->Process->ImageSection->
	ImageSectionObject->ImageInformation.TransferAddress;
    Context.rsp = Thread->StackTop;
    Context.rbp = Thread->StackTop;
    Context->gs_base = Thread->TEBClientAddr;
}
