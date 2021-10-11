#include <nt.h>
#include <stdarg.h>
#include <string.h>

PCSTR SMSS_BANNER = "\nNeptune OS Session Manager\n\n";

/* TODO: Move this to the CRT headers */
int _vsnprintf(char *buf, size_t size, const char *fmt, va_list args);

#define RET_ERR_EX(Expr, OnError)					\
    {NTSTATUS __tmp_rete = (Expr); if (!NT_SUCCESS(__tmp_rete)) {	\
	    DbgPrint("Expression %s in function %s @ %s:%d returned"	\
		     " error 0x%x\n",					\
		     #Expr, __func__, __FILE__, __LINE__, __tmp_rete);	\
	    {OnError;} return __tmp_rete; }}
#define RET_ERR(Expr)	RET_ERR_EX(Expr, {})

#define DECLARE_UNICODE_STRING(Name, Ptr, Length)			\
    UNICODE_STRING Name = { .Length = Length, .MaximumLength = Length,	\
	.Buffer = Ptr }

NTSTATUS SmPrint(PCSTR Format, ...)
{
    char buf[512];
    va_list arglist;
    va_start(arglist, Format);
    int n = _vsnprintf(buf, sizeof(buf), Format, arglist);
    va_end(arglist);
    if (n <= 0) {
	return STATUS_UNSUCCESSFUL;
    }
    NtDisplayStringA(buf);
    return STATUS_SUCCESS;
}

NTSTATUS SmLoadBootDrivers()
{
    PCSTR DriverToLoad = "\\BootModules\\null.sys";
    SmPrint("Loading driver %s... ", DriverToLoad);
    RET_ERR_EX(NtLoadDriverA(DriverToLoad),
	       {
		   SmPrint("FAILED\n");
		   /* FREE */
	       });
    SmPrint("OK\n");
    return STATUS_SUCCESS;
}

NTAPI VOID NtProcessStartup(PPEB Peb)
{
    SmPrint(SMSS_BANNER);
    SmLoadBootDrivers();

    while (1);
}
