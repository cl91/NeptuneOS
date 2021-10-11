#include "../psp.h"

VOID PspInitializeThreadContext(IN PTHREAD Thread,
				IN PTHREAD_CONTEXT Context)
{
    assert(Thread != NULL);
    assert(Thread->Process != NULL);
    assert(Thread->IpcBufferClientAddr != 0);
    assert(Thread->TebClientAddr);
    assert(Thread->StackTop);
    assert(Context != NULL);
    Context->rcx = Thread->IpcBufferClientAddr;
    Context->rdx = Thread->SystemDllTlsBase;
    Context->rip = (MWORD) PspSystemDllSection->ImageSectionObject->ImageInformation.TransferAddress;
    Context->rsp = Thread->StackTop;
    Context->rbp = Thread->StackTop;
    Context->gs_base = Thread->TebClientAddr;
}
