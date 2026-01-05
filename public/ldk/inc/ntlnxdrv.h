/*++

Copyright (c) 2026  Dr. Chang Liu, PhD.

Module Name:

    ntlnxdrv.h

Abstract:

    This header file defines the interfaces shared between the PE sub-component of
    a linkable and extendable driver (lnxdrv) and its ELF sub-component. A lnxdrv
    (a name deliberately chosen that evokes the name of "Linux driver") contains
    two portions: a PE part which is a standard Neptune OS driver that speaks the
    standard Neptune OS driver interface, and an ELF part which is an ELF executable
    that is loaded into the process of the PE driver object and communicates with
    the PE driver object through a standard interface, defined in this header. The
    term "linkable" refers to the fact that we we are implementing is essentially a
    form of runtime linking of an ELF object with a PE object. When the ELF object
    is loaded into the process of the PE driver object, the PE code supplies the
    entry point of the ELF executable with an "import table", containing function
    pointers that the ELF object can call. The ELF entry point in turn returns an
    "export table" containing function pointers for the PE object. Due to the ABI
    differences between PE and ELF, the PE and ELF function pointers must be marked
    with the appropriate ABI attributes (MS_ABI and ELF_ABI), so the compiler can
    use the correct calling conventions when calling these function pointers (this
    is effectively what Microsoft calls "thunking", a technique used, for instance,
    to call 16-bit routines from 32-bit code). All callback routines must also be
    appropriately marked with an ABI attribute.

Revision History:

    2026-01-05  File created
*/

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

typedef struct _LNX_DRV_IMPORT_TABLE {
} LNX_DRV_IMPORT_TABLE, *PLNX_DRV_IMPORT_TABLE;

typedef struct _LNX_DRV_EXPORT_TABLE {
} LNX_DRV_EXPORT_TABLE, *PLNX_DRV_EXPORT_TABLE;

typedef ELF_ABI NTSTATUS (LNX_DRV_ENTRY_POINT)(IN PLNX_DRV_IMPORT_TABLE ImportTable,
					       OUT PLNX_DRV_EXPORT_TABLE *ExportTable);
