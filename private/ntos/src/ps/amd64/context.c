#include "../psp.h"

VOID PspInitializeThreadContext(IN PTHREAD Thread,
				IN PTHREAD_CONTEXT Context)
{
    assert(Thread != NULL);
    assert(Thread->Process != NULL);
    assert(Thread->IpcBufferClientAddr != 0);
    assert(Thread->TebClientAddr);
    assert(Thread->InitialStackTop);
    assert(Context != NULL);
    Context->rcx = Thread->IpcBufferClientAddr;
    Context->rdx = Thread->SystemDllTlsBase;
    Context->rip = (MWORD) PspSystemDllSection->ImageSectionObject->ImageInformation.TransferAddress;
    Context->rsp = Thread->InitialStackTop;
    Context->rbp = Thread->InitialStackTop;
    Context->gs_base = Thread->TebClientAddr;
}

VOID PspInitializeSystemThreadContext(IN PSYSTEM_THREAD Thread,
				      IN PTHREAD_CONTEXT Context,
				      IN PSYSTEM_THREAD_ENTRY EntryPoint)
{
    assert(Thread != NULL);
    assert(Thread->IpcBuffer != NULL);
    assert(Thread->TlsBase != NULL);
    assert(Thread->StackTop != NULL);
    assert(Context != NULL);
    assert(EntryPoint != NULL);
    PPVOID StackTop = (PPVOID)Thread->StackTop;
    /* Set the return address to NULL since PspSystemThreadStartup never returns */
    StackTop[-1] = NULL;
    Context->rdi = (MWORD)Thread->IpcBuffer;
    Context->rsi = (MWORD)EntryPoint;
    Context->rip = (MWORD)PspSystemThreadStartup;
    Context->rsp = (MWORD)&StackTop[-1];
    Context->rbp = (MWORD)Thread->StackTop;
    Context->fs_base = (MWORD)Thread->TlsBase;
}
