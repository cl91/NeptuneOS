#pragma once

#include <stdarg.h>
#include <nt.h>
#include <structures_gen.h>

#if defined(CONFIG_DEBUG_BUILD) || (defined(_DEBUG) && !defined(NDEBUG))
VOID vDbgPrint(PCSTR Format, va_list args);
VOID DbgPrint(PCSTR Format, ...) __attribute__ ((format(printf, 1, 2)));
#else
#define DbgPrint(...)
#endif

#define DbgTrace(...) { DbgPrint("%s:  ", __func__); DbgPrint(__VA_ARGS__); }

PCSTR RtlDbgCapTypeToStr(cap_tag_t Type);

#define RET_ERR_EX(Expr, OnError)					\
    {NTSTATUS Status = (Expr); if (!NT_SUCCESS(Status)) {		\
	    DbgPrint("Expression %s in function %s @ %s:%d returned"	\
		     " error 0x%x\n",					\
		     #Expr, __func__, __FILE__, __LINE__, Status);	\
	    {OnError;} return Status; }}
#define RET_ERR(Expr)	RET_ERR_EX(Expr, {})

#define IF_ERR_GOTO(Label, Status, Expr)				\
    Status = (Expr);							\
    if (!NT_SUCCESS(Status)) {						\
	DbgPrint("Expression %s in function %s @ %s:%d returned"	\
		 " error 0x%x\n",					\
		 #Expr, __func__, __FILE__, __LINE__, Status);		\
	goto Label;							\
    }

#define DPRINT1		DbgPrint
