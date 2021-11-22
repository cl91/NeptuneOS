#include <nt.h>
#include <stdarg.h>
#include <string.h>

/* TODO: Move this to the CRT headers */
int _vsnprintf(char *buf, size_t size, const char *fmt, va_list args);

#define RET_ERR_EX(Expr, OnError)					\
    {NTSTATUS Status = (Expr); if (!NT_SUCCESS(Status)) {		\
	    DbgPrint("Expression %s in function %s @ %s:%d returned"	\
		     " error 0x%x\n",					\
		     #Expr, __func__, __FILE__, __LINE__, Status);	\
	    {OnError;} return Status; }}
#define RET_ERR(Expr)	RET_ERR_EX(Expr, {})

#define DECLARE_UNICODE_STRING(Name, Ptr, Length)			\
    UNICODE_STRING Name = { .Length = Length, .MaximumLength = Length,	\
	.Buffer = Ptr }

#define ARRAY_LENGTH(x)		(sizeof(x) / sizeof((x)[0]))
