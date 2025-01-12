#include <ntdll.h>

VOID KiDispatchUserException(IN PEXCEPTION_RECORD ExceptionRecord,
			     IN PCONTEXT Context)
{
    DbgTrace("ExceptionRecord %p Context %p\n", ExceptionRecord, Context);
    while (1) ;
}
