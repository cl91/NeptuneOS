/*++

Copyright (c) 2026  Dr. Chang Liu, PhD.

Module Name:

    ntlnxdrv.h

Abstract:

    This header file defines the interfaces shared between the PE sub-component of
    a linkable extension driver (lnxdrv) and its ELF sub-component. A lnxdrv (a name
    deliberately chosen that evokes the connotation of a "Linux driver") contains
    two portions: a PE portion that is a standard NT driver speaking the standard
    NT driver interface, and an ELF half that is an ELF executable loaded into the
    process of the PE driver object and communicating with the PE driver object
    through a standard interface, defined in this header. The term "linkable" refers
    to the fact that what we are implementing is effectively a form of runtime
    linking of an ELF object with a PE object. When the ELF object is loaded into
    the process of the PE driver object, the PE code supplies the entry point of
    the ELF executable with an "import table", containing function pointers that
    the ELF object can call. The ELF entry point in turn returns an "export table"
    containing function pointers for the PE object to call. Due to ABI differences
    between PE and ELF, the function pointers in the import and export tables must
    be marked with an appropriate ABI attribute (MS_ABI or ELF_ABI), so the compiler
    can use the correct calling conventions when calling these function pointers
    (this is essentially the same technique that Microsoft calls "thunking", which
    is used, for instance, in the Win16 subsystem of NT to call 32-bit routines
    from 16-bit code). Likewise, all callback routines that cross the PE/ELF border
    must also be appropriately marked with an ABI attribute.

    The ELF part of the lnxdrv should include this master header and should NOT
    include the lnxdrv.h master header, which is for the PE part of the driver to
    include.

Revision History:

    2026-01-05  File created
*/

#pragma once

#include <ntdef.h>
#include <ntstatus.h>

#ifdef _M_AMD64
#define MS_ABI __attribute__((ms_abi))
#define ELF_ABI __attribute__((sysv_abi))
#else
/* On i386 and arm64, there is no difference between the default calling conventions
 * used by PE and ELF. */
#define MS_ABI
#define ELF_ABI
#endif

typedef VOID ELF_ABI (*LNX_DRV_THREAD_ENTRY)(PVOID);

typedef struct _LNX_DRV_IMPORT_TABLE {
    VOID (MS_ABI *DbgPrint)(IN PCSTR String);
    PVOID (MS_ABI *AllocateMemory)(IN SIZE_T Size);
    VOID (MS_ABI *FreeMemory)(IN PCVOID Ptr);
    VOID (MS_ABI *SetEvent)(IN PVOID Event);
    VOID (MS_ABI *WaitForSingleObject)(IN HANDLE Event, IN BOOLEAN Alertable);
    VOID (MS_ABI __attribute((noreturn)) *RaiseStatus)(IN NTSTATUS Status);
} LNX_DRV_IMPORT_TABLE, *PLNX_DRV_IMPORT_TABLE;

typedef struct _LNX_DRV_EXPORT_TABLE {
    VOID (ELF_ABI *QueryDriverInfo)(VOID);
    VOID (ELF_ABI *QueryDeviceInfo)(VOID);
} LNX_DRV_EXPORT_TABLE, *PLNX_DRV_EXPORT_TABLE;

typedef NTSTATUS (ELF_ABI LNX_DRV_ENTRY_POINT)(IN PLNX_DRV_IMPORT_TABLE ImportTable,
					       OUT PLNX_DRV_EXPORT_TABLE ExportTable);
typedef LNX_DRV_ENTRY_POINT *PLNX_DRV_ENTRY_POINT;
