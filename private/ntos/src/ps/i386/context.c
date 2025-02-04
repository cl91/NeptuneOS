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
    Context->eip = Thread->Process->UserExceptionDispatcher;
    Context->esp = Thread->InitInfo.StackTop;
    Context->ebp = Thread->InitInfo.StackTop;
    Context->fs_base = TibClientAddr;
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
    /* GCC expects that a C function is always entered via a call
     * instruction and that the stack is 16-byte aligned before such an
     * instruction (leaving it 16-byte aligned + 1 word from the
     * implicit push when the function is entered). */
    PPVOID StackTop = (PPVOID)(Thread->StackTop - 16);
    StackTop[1] = EntryPoint;
    StackTop[0] = Thread->IpcBuffer;
    /* Set the return address to NULL since PspSystemThreadStartup never returns */
    StackTop[-1] = NULL;
    Context->eip = (MWORD)PspSystemThreadStartup;
    Context->esp = (MWORD)&StackTop[-1];
    Context->ebp = (MWORD)Thread->StackTop;
    Context->gs_base = (MWORD)Thread->TlsBase;
}
