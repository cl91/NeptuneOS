#include "../psp.h"

VOID PspInitializeThreadContext(IN PTHREAD Thread)
{
    assert(Thread != NULL);
    assert(Thread->Process != NULL);
    Thread->Context.eip = (MWORD) Thread->Process->ImageSection->
	ImageSectionObject->ImageInformation.TransferAddress;
    Thread->Context.esp = THREAD_STACK_END;
    Thread->Context.ebp = THREAD_STACK_END;
}
