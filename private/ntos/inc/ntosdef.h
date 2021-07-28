#pragma once

#include <sel4/sel4.h>

typedef seL4_Word MWORD;
#define MWORD_BYTES	(sizeof(MWORD))
#define MWORD_BITS	(MWORD_BYTES * 8)

#define ARRAY_LENGTH(x)		(sizeof(x) / sizeof((x)[0]))
#define COMPILE_ASSERT(name, expr)	typedef int __ntos_assert_failed_##name[(expr) ? 1 : -1]

/* NTSTATUS Bits:
 * 0--15   Status code
 * 16--28  Facility
 * 29      Custom code flag
 * 30--31  Severity
 */

#define FACILITY_SEL4		0x44
#define FACILITY_NTOS		0x45

#define SEL4_ERROR(Code)	((NTSTATUS)(Code | (FACILITY_SEL4 << 16) | ERROR_SEVERITY_ERROR))
#define NTOS_ERROR(Code)	((NTSTATUS)(Code | (FACILITY_NTOS << 16) | ERROR_SEVERITY_ERROR))

#define STATUS_NTOS_BUG				NTOS_ERROR(1)
#define STATUS_NTOS_UNIMPLEMENTED		NTOS_ERROR(1)

#define RET_ERR_EX(Expr, OnError)					\
    {NTSTATUS __tmp_rete = (Expr); if (!NT_SUCCESS(__tmp_rete)) {	\
	    DbgPrint("Expression %s in function %s @ %s:%d returned"	\
		     " error 0x%x\n",					\
		     #Expr, __func__, __FILE__, __LINE__, __tmp_rete);	\
	    {OnError;} return __tmp_rete; }}
#define RET_ERR(Expr)	RET_ERR_EX(Expr, {})
#define ExAllocatePoolEx(Var, Type, Size, Tag, OnError)			\
    Type *Var = (Type *)ExAllocatePoolWithTag(Size, Tag);		\
    if ((Var) == NULL) {						\
	DbgPrint("Allocation of 0x%zx bytes for variable %s of type"	\
		 " (%s *) failed in function %s @ %s:%d\n",		\
		 Size, #Var, #Type, __func__, __FILE__, __LINE__);	\
	{OnError;} return STATUS_NO_MEMORY; }

#if defined(__GNUC__) || defined(__clang__)
#define __packed	__attribute__((__packed__))
#define __aligned(x)	__attribute__((aligned(x)))
#define __section(x)	__attribute__((section(x)))
#else
#error "Use a real compiler you pleb"
#endif

static inline VOID InvalidateListEntry(IN PLIST_ENTRY ListEntry)
{
    ListEntry->Flink = ListEntry->Blink = NULL;
}

static inline ULONG GetListLength(IN PLIST_ENTRY ListEntry)
{
    ULONG Length = 0;
    for (PLIST_ENTRY Ptr = ListEntry->Flink; Ptr != ListEntry; Ptr = Ptr->Flink) {
	Length++;
    }
    return Length;
}

#define LoopOverList(Entry, ListHead, Type, Field)			\
    for (Type *Entry = CONTAINING_RECORD((ListHead)->Flink, Type, Field); \
    &(Entry)->Field != (ListHead);					\
    Entry = CONTAINING_RECORD((Entry)->Field.Flink, Type, Field))

#define ReverseLoopOverList(Entry, ListHead, Type, Field)		\
    for (Type *Entry = CONTAINING_RECORD((ListHead)->Blink, Type, Field); \
    &(Entry)->Field != (ListHead);					\
    Entry = CONTAINING_RECORD((Entry)->Field.Blink, Type, Field))

/*
 * Additional alignment macros
 */
#define IS_ALIGNED(addr, type)		((ULONG_PTR)(addr) == ALIGN_DOWN_BY(addr, type))
