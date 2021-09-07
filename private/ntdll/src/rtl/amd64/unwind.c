#include <ntdll.h>

VOID NTAPI RtlUnwindEx(IN OPTIONAL PVOID TargetFrame,
		       IN OPTIONAL PVOID TargetIp,
		       IN OPTIONAL PEXCEPTION_RECORD ExceptionRecord,
		       IN PVOID ReturnValue,
		       IN PCONTEXT ContextRecord,
		       IN OPTIONAL struct _UNWIND_HISTORY_TABLE *HistoryTable)
{
    /* TODO */
}

VOID NTAPI RtlUnwind(IN PVOID TargetFrame OPTIONAL,
		     IN PVOID TargetIp OPTIONAL,
		     IN PEXCEPTION_RECORD ExceptionRecord OPTIONAL,
		     IN PVOID ReturnValue)
{
    /* TODO */
}
