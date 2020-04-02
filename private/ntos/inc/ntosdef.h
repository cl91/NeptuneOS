#pragma once

#include <sel4/sel4.h>
typedef seL4_Word MWORD;
#define MWORD_BITS	((sizeof(MWORD))*8)

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

#define RET_IF_ERR(Expr)	{NTSTATUS Error = (Expr); if (!NT_SUCCESS(Error)) { return Error; }}
