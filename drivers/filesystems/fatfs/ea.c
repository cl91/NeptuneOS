/*
 * PROJECT:     FAT Filesystem
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Extended attributes handlers
 * COPYRIGHT:   Copyright 1998 Jason Filby <jasonfilby@yahoo.com>
 */

/* INCLUDES *****************************************************************/

#include "fatfs.h"

/* FUNCTIONS *****************************************************************/

NTSTATUS FatSetExtendedAttributes(PFILE_OBJECT FileObject,
				  PVOID Ea,
				  ULONG EaLength)
{
    UNREFERENCED_PARAMETER(FileObject);
    UNREFERENCED_PARAMETER(Ea);
    UNREFERENCED_PARAMETER(EaLength);

    return STATUS_EAS_NOT_SUPPORTED;
}
