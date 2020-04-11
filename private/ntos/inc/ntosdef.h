#pragma once

#include <sel4/sel4.h>
typedef seL4_Word MWORD;

#ifdef _M_IX86
#define MWORD_BITS	(32)
#define MWORD_BYTES	(4)
#define MWORD_SHIFT	(2)
#elif defined(_M_AMD64)
#define MWORD_BITS	(64)
#define MWORD_BYTES	(8)
#define MWORD_SHIFT	(3)
#endif

/* NTSTATUS Bits:
 * 0--15   Status code
 * 16--28  Facility
 * 29      Custom code flag
 * 30--31  Severity
 */

#define FACILITY_SEL4		0x44
#define FACILITY_NTOS_EXEC	0x45

#define SEL4_ERROR(Code)	((NTSTATUS)(Code | (FACILITY_SEL4 << 16) | ERROR_SEVERITY_ERROR))
#define NTOS_EXEC_ERROR(Code)	((NTSTATUS)(Code | (FACILITY_NTOS_EXEC << 16) | ERROR_SEVERITY_ERROR))

#define STATUS_NTOS_EXEC_INVALID_ARGUMENT	NTOS_EXEC_ERROR(1)
#define STATUS_NTOS_EXEC_CAPSPACE_EXHAUSTION	NTOS_EXEC_ERROR(2)
#define STATUS_NTOS_EXEC_OUT_OF_MEMORY		NTOS_EXEC_ERROR(3)

#define RET_IF_ERR(Expr)	{NTSTATUS Error = (Expr); if (!NT_SUCCESS(Error)) { return Error; }}

#if defined(__GNUC__) || defined(__clang__)
#define __packed         __attribute__((__packed__))
#define __aligned(x)    __attribute__ ((aligned(x)))
#else
#error "Use a real compiler you pleb"
#endif

static inline VOID InvalidateListEntry(IN PLIST_ENTRY ListEntry)
{
    ListEntry->Flink = ListEntry->Blink = NULL;
}
