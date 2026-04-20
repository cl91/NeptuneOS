#include <ntdll.h>

VOID KiDispatchUserException(IN PCONTEXT Context,
			     IN PEXCEPTION_RECORD ExceptionRecord)
{
    DbgTrace("ExceptionRecord %p Context %p\n", ExceptionRecord, Context);
    while (1) ;
}
