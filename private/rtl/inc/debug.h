#pragma once

#include <stdarg.h>
#include <nt.h>
#include <structures_gen.h>

#ifdef CONFIG_DEBUG_BUILD
VOID vDbgPrint(PCSTR Format, va_list args);
VOID DbgPrint(PCSTR Format, ...) __attribute__ ((format(printf, 1, 2)));
#else
#define DbgPrint(...)
#endif

#define DbgTrace(...) { DbgPrint("%s:  ", __func__); DbgPrint(__VA_ARGS__); }

PCSTR RtlDbgCapTypeToStr(cap_tag_t Type);

#define RET_ERR_EX(Expr, OnError)					\
    {NTSTATUS __tmp_rete = (Expr); if (!NT_SUCCESS(__tmp_rete)) {	\
	    DbgPrint("Expression %s in function %s @ %s:%d returned"	\
		     " error 0x%x\n",					\
		     #Expr, __func__, __FILE__, __LINE__, __tmp_rete);	\
	    {OnError;} return __tmp_rete; }}
#define RET_ERR(Expr)	RET_ERR_EX(Expr, {})
#define ExAllocatePoolEx(Var, Type, Size, Tag, OnError)			\
    {} Type *Var = (Type *)ExAllocatePoolWithTag(Size, Tag);		\
    if ((Var) == NULL) {						\
	DbgPrint("Allocation of 0x%zx bytes for variable %s of type"	\
		 " (%s *) failed in function %s @ %s:%d\n",		\
		 Size, #Var, #Type, __func__, __FILE__, __LINE__);	\
	{OnError;} return STATUS_NO_MEMORY; }

#define DPRINT1		DbgPrint
