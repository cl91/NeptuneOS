#include "ldrp.h"

/*
 * This can only be called after the caller has validated the image.
 */
PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader(IN PVOID Base)
{
    PIMAGE_NT_HEADERS NtHeader;

    /* Call the new API */
    RtlpImageNtHeaderEx(RTL_IMAGE_NT_HEADER_EX_FLAG_NO_RANGE_CHECK,
			Base, 0, &NtHeader);
    return NtHeader;
}
