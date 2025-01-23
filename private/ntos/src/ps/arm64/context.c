#include "../psp.h"

VOID PspInitializeThreadContext(IN PTHREAD Thread,
				IN PTHREAD_CONTEXT Context)
{
    assert(Thread != NULL);
    assert(Thread->Process != NULL);
    assert(Thread->IpcBufferClientAddr != 0);
    assert(Thread->InitInfo.StackTop);
    assert(Context != NULL);
    MWORD TibClientAddr = Thread->IpcBufferClientAddr + NT_TIB_OFFSET;
    Context->_FASTCALL_FIRST_PARAM = TibClientAddr;
    Context->pc = Thread->Process->UserExceptionDispatcher;
    Context->sp = Thread->InitInfo.StackTop;
    Context->x29 = Thread->InitInfo.StackTop;
    Context->x18 = TibClientAddr;
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
    Context->x0 = (MWORD)Thread->IpcBuffer;
    Context->x1 = (MWORD)EntryPoint;
    Context->pc = (MWORD)PspSystemThreadStartup;
    Context->sp = (MWORD)Thread->StackTop;
    Context->x29 = (MWORD)Thread->StackTop;
    Context->tpidr_el0 = (MWORD)Thread->TlsBase;
}
