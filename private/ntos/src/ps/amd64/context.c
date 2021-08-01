#include "../psp.h"

VOID PspInitializeThreadContext(IN PTHREAD Thread)
{
    assert(Thread != NULL);
    assert(Thread->Process != NULL);
    Thread->Context.rip = (MWORD) Thread->Process->ImageSection->
	ImageSectionObject->ImageInformation.TransferAddress;
    Thread->Context.rsp = THREAD_STACK_END;
    Thread->Context.rbp = THREAD_STACK_END;
}
