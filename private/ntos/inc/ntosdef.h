#pragma once

#include <services.h>

#define ARRAY_LENGTH(x)		(sizeof(x) / sizeof((x)[0]))

#define UNIMPLEMENTED					\
    {							\
	HalVgaPrint("%s UNIMPLEMENTED\n", __func__);	\
	return STATUS_NOT_IMPLEMENTED;			\
    }

/* NTSTATUS Bits:
 * 0--15   Status code
 * 16--28  Facility
 * 29      Customer code flag
 * 30--31  Severity
 */

#define CUSTOMER_FLAG_BIT	29

#define FACILITY_ASYNC		0x43
#define FACILITY_SEL4		0x44
#define FACILITY_NTOS		0x45

#define ASYNC_SUCCESS(Code)	((NTSTATUS)(Code | (FACILITY_ASYNC << 16) | (1UL << CUSTOMER_FLAG_BIT) | ERROR_SEVERITY_SUCCESS))
#define ASYNC_INFORMATION(Code)	((NTSTATUS)(Code | (FACILITY_ASYNC << 16) | (1UL << CUSTOMER_FLAG_BIT) | ERROR_SEVERITY_INFORMATIONAL))
#define ASYNC_ERROR(Code)	((NTSTATUS)(Code | (FACILITY_ASYNC << 16) | (1UL << CUSTOMER_FLAG_BIT) | ERROR_SEVERITY_ERROR))
#define SEL4_ERROR(Code)	((NTSTATUS)(Code | (FACILITY_SEL4 << 16) | (1UL << CUSTOMER_FLAG_BIT) | ERROR_SEVERITY_ERROR))
#define NTOS_SUCCESS(Code)	((NTSTATUS)(Code | (FACILITY_NTOS << 16) | (1UL << CUSTOMER_FLAG_BIT) | ERROR_SEVERITY_SUCCESS))
#define NTOS_INFORMATION(Code)	((NTSTATUS)(Code | (FACILITY_NTOS << 16) | (1UL << CUSTOMER_FLAG_BIT) | ERROR_SEVERITY_INFORMATIONAL))
#define NTOS_ERROR(Code)	((NTSTATUS)(Code | (FACILITY_NTOS << 16) | (1UL << CUSTOMER_FLAG_BIT) | ERROR_SEVERITY_ERROR))

#define IS_ASYNC_STATUS(Code)			((((((ULONG)(Code)) >> 16) << 3) >> 3) == FACILITY_ASYNC)

#define STATUS_ASYNC_PENDING			ASYNC_INFORMATION(1)
#define STATUS_NTOS_BUG				NTOS_ERROR(1)
#define STATUS_NTOS_NO_REPLY			NTOS_INFORMATION(2)
#define STATUS_NTOS_DRIVER_ALREADY_LOADED	NTOS_SUCCESS(3)

#define assert_ret(expr)	if (!(expr)) { return STATUS_NTOS_BUG; }


/*
 * Additional alignment macros
 */
#define IS_ALIGNED_BY(addr, align)	((ULONG_PTR)(addr) == ALIGN_DOWN_BY(addr, align))
#define IS_ALIGNED(addr, type)		((ULONG_PTR)(addr) == ALIGN_DOWN(addr, type))
