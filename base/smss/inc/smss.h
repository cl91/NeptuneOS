#include <nt.h>
#include <stdarg.h>
#include <string.h>
#include <stdio.h>

#define DbgTrace(...) { DbgPrint("%s:  ", __func__); DbgPrint(__VA_ARGS__); }

#define RET_ERR_EX(Expr, OnError)					\
    {NTSTATUS Status = (Expr); if (!NT_SUCCESS(Status)) {		\
	    DbgPrint("Expression %s in function %s @ %s:%d returned"	\
		     " error 0x%x\n",					\
		     #Expr, __func__, __FILE__, __LINE__, Status);	\
	    {OnError;} return Status; }}
#define RET_ERR(Expr)	RET_ERR_EX(Expr, {})

#define DECLARE_UNICODE_STRING(Name, Ptr, Len)				\
    UNICODE_STRING Name = { .Length = Len, .MaximumLength = Len,	\
	.Buffer = Ptr }

#define ARRAY_LENGTH(x)		(sizeof(x) / sizeof((x)[0]))

/* main.c */
NTSTATUS SmPrint(PCSTR Format, ...) __attribute__((format(printf, 1, 2)));

/* reg.c */
NTSTATUS SmInitRegistry();
