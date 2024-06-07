/******************************************************************************
 *
 * Name: acntos.h - OS specific defines, etc. for Neptune OS
 *
 *****************************************************************************/

#pragma once

#ifdef _WIN64
#define ACPI_MACHINE_WIDTH 64
#define COMPILER_DEPENDENT_INT64 long
#define COMPILER_DEPENDENT_UINT64 unsigned long
#else
#define ACPI_MACHINE_WIDTH 32
#define COMPILER_DEPENDENT_INT64 long long
#define COMPILER_DEPENDENT_UINT64 unsigned long long
#define ACPI_USE_NATIVE_DIVIDE
#endif

#define ACPI_USE_SYSTEM_CLIBRARY
#define ACPI_USE_LOCAL_CACHE
#define ACPI_USE_SYSTEM_INTTYPES
#define ACPI_MUTEX_TYPE ACPI_OSL_MUTEX

#include <ntddk.h>
#include <hal.h>
#include <ctype.h>

typedef unsigned int UINT32;
typedef int INT32;
typedef USHORT UINT16;
typedef UCHAR UINT8;

/* Flush CPU cache - used when going to sleep. Wbinvd or similar. */
/* TODO: Call seL4_BenchmarkFlushCaches(). */
#define ACPI_FLUSH_CPU_CACHE()

/* Since DPCs and work items are both processed in the main thread
 * and are never preempted, we do not need mutexes to protect data
 * structures accessed by DPCs and work items. */
#define ACPI_USE_ALTERNATE_PROTOTYPE_AcpiOsCreateMutex
#define ACPI_USE_ALTERNATE_PROTOTYPE_AcpiOsDeleteMutex
#define ACPI_USE_ALTERNATE_PROTOTYPE_AcpiOsAcquireMutex
#define ACPI_USE_ALTERNATE_PROTOTYPE_AcpiOsReleaseMutex
#define AcpiOsCreateMutex(OutHandle) ({ (VOID)(OutHandle); AE_OK; })
#define AcpiOsDeleteMutex(Handle) ({ (VOID)(Handle); ; })
#define AcpiOsAcquireMutex(Handle, Timeout) ({ (VOID)(Handle); (VOID)(Timeout); AE_OK; })
#define AcpiOsReleaseMutex(Handle) ({ (VOID)(Handle); ; })

/* Likewise, since there is only one thread (ie. the main thread) beside
 * the ISR thread, acquiring a semaphore or a spinlock can simply be
 * defined as acquiring the interrupt mutex. */
#define ACPI_SEMAPHORE PKINTERRUPT
#define ACPI_SPINLOCK PKINTERRUPT
#define ACPI_USE_ALTERNATE_PROTOTYPE_AcpiOsDeleteSemaphore
#define ACPI_USE_ALTERNATE_PROTOTYPE_AcpiOsWaitSemaphore
#define ACPI_USE_ALTERNATE_PROTOTYPE_AcpiOsSignalSemaphore
#define AcpiOsDeleteSemaphore(Handle) ({ (VOID)(Handle); AE_OK; })
#define AcpiOsWaitSemaphore(Handle, Units, Timeout)			\
    ({ IoAcquireInterruptMutex(Handle); (VOID)(Units); (VOID)(Timeout); AE_OK; })
#define AcpiOsSignalSemaphore(Handle, Units)			\
    ({ IoReleaseInterruptMutex(Handle); (VOID)(Units); AE_OK; })
#define ACPI_USE_ALTERNATE_PROTOTYPE_AcpiOsDeleteLock
#define ACPI_USE_ALTERNATE_PROTOTYPE_AcpiOsAcquireLock
#define ACPI_USE_ALTERNATE_PROTOTYPE_AcpiOsReleaseLock
#define AcpiOsDeleteLock(Handle) ({ (VOID)(Handle); ; })
#define AcpiOsAcquireLock(Handle) ({ IoAcquireInterruptMutex(Handle); 0; })
#define AcpiOsReleaseLock(Handle, Flags)			\
    ({ IoReleaseInterruptMutex(Handle); (VOID)(Flags); })
