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
    Context->eax = Thread->EntryPoint;
    Context->ecx = Thread->IpcBufferClientAddr;
    Context->edx = Thread->SystemDllTlsBase;
    Context->eip = (MWORD) PspSystemDllSection->ImageSectionObject->ImageInformation.TransferAddress;
    Context->esp = Thread->StackTop;
    Context->ebp = Thread->StackTop;
    Context->fs_base = Thread->TebClientAddr;
}
