/*
 * COPYRIGHT:         See COPYING in the top level directory
 * PROJECT:           ReactOS system libraries
 * PURPOSE:           Security manager
 * FILE:              lib/rtl/sid.c
 * PROGRAMER:         David Welch <welch@cwcom.net>
 */

/* INCLUDES *****************************************************************/

#include "rtlp.h"
#include <stdio.h>

#define TAG_SID 'diSp'

/* FUNCTIONS ***************************************************************/

NTAPI BOOLEAN RtlValidSid(IN PSID Sid_)
{
    PISID Sid = Sid_;

    /* Use SEH in case any pointer is invalid */
    __try {
	/* Validate the revision and subauthority count */
	if ((Sid) &&
	    (((Sid->Revision & 0xF) != SID_REVISION) ||
	     (Sid->SubAuthorityCount > SID_MAX_SUB_AUTHORITIES))) {
	    /* It's not, fail */
	    return FALSE;
	}
    } __except(EXCEPTION_EXECUTE_HANDLER) {
	/* Access violation, SID is not valid */
	return FALSE;
    }

    /* All good */
    return TRUE;
}

/*
 * @implemented
 */
NTAPI ULONG RtlLengthRequiredSid(IN ULONG SubAuthorityCount)
{
    /* Return the required length */
    return (ULONG) FIELD_OFFSET(SID, SubAuthority[SubAuthorityCount]);
}

/*
 * @implemented
 */
NTAPI NTSTATUS RtlInitializeSid(IN PSID Sid_,
				IN PSID_IDENTIFIER_AUTHORITY IdentifierAuthority,
				IN UCHAR SubAuthorityCount)
{
    PISID Sid = Sid_;

    /* Fill out the header */
    Sid->Revision = SID_REVISION;
    Sid->SubAuthorityCount = SubAuthorityCount;
    Sid->IdentifierAuthority = *IdentifierAuthority;

    /* All good */
    return STATUS_SUCCESS;
}

/*
 * @implemented
 */
NTAPI PULONG RtlSubAuthoritySid(IN PSID Sid_,
				IN ULONG SubAuthority)
{
    PISID Sid = Sid_;

    /* Return the offset */
    return (PULONG) &Sid->SubAuthority[SubAuthority];
}

/*
 * @implemented
 */
NTAPI PUCHAR RtlSubAuthorityCountSid(IN PSID Sid_)
{
    PISID Sid = Sid_;

    /* Return the offset to the count */
    return &Sid->SubAuthorityCount;
}

/*
 * @implemented
 */
NTAPI PSID_IDENTIFIER_AUTHORITY RtlIdentifierAuthoritySid(IN PSID Sid_)
{
    PISID Sid = Sid_;

    /* Return the offset to the identifier authority */
    return &Sid->IdentifierAuthority;
}

/*
 * @implemented
 */
NTAPI BOOLEAN RtlEqualSid(IN PSID Sid1_,
			  IN PSID Sid2_)
{
    PISID Sid1 = Sid1_, Sid2 = Sid2_;

    /* Quick compare of the revision and the count */
    if (*(PUSHORT) & Sid1->Revision != *(PUSHORT) & Sid2->Revision)
	return FALSE;

    /* Get the length and compare it the long way */
    return RtlEqualMemory(Sid1, Sid2, RtlLengthSid(Sid1));
}

/*
 * @implemented
 */
NTAPI ULONG RtlLengthSid(IN PSID Sid_)
{
    PISID Sid = Sid_;

    /* The offset to the last index + 1 (since it's a count) is the length */
    return (ULONG) FIELD_OFFSET(SID, SubAuthority[Sid->SubAuthorityCount]);
}

/*
 * @implemented
 */
NTAPI NTSTATUS RtlCopySid(IN ULONG BufferLength,
			  IN PSID Dest,
			  IN PSID Src)
{
    ULONG SidLength;

    /* Make sure the buffer is large enough */
    SidLength = RtlLengthSid(Src);
    if (SidLength > BufferLength)
	return STATUS_BUFFER_TOO_SMALL;

    /* And then copy the SID */
    RtlMoveMemory(Dest, Src, SidLength);
    return STATUS_SUCCESS;
}

/*
 * @implemented
 */
NTAPI PVOID RtlFreeSid(IN PSID Sid)
{
    /* Free the SID and always return NULL */
    RtlpFreeMemory(Sid, TAG_SID);
    return NULL;
}

/*
 * @implemented
 */
NTAPI BOOLEAN RtlEqualPrefixSid(IN PSID Sid1_,
				IN PSID Sid2_)
{
    PISID Sid1 = Sid1_, Sid2 = Sid2_;
    ULONG i;

    /* Revisions have to match */
    if (Sid1->Revision != Sid2->Revision)
	return FALSE;

    /* The identifier authorities have to match */
    if ((Sid1->IdentifierAuthority.Value[0] == Sid2->IdentifierAuthority.Value[0])
	&& (Sid1->IdentifierAuthority.Value[1] == Sid2->IdentifierAuthority.Value[1])
	&& (Sid1->IdentifierAuthority.Value[2] == Sid2->IdentifierAuthority.Value[2])
	&& (Sid1->IdentifierAuthority.Value[3] == Sid2->IdentifierAuthority.Value[3])
	&& (Sid1->IdentifierAuthority.Value[4] == Sid2->IdentifierAuthority.Value[4])
	&& (Sid1->IdentifierAuthority.Value[5] == Sid2->IdentifierAuthority.Value[5])) {
	/* The subauthority counts have to match */
	if (Sid1->SubAuthorityCount == Sid2->SubAuthorityCount) {
	    /* If there aren't any in SID1, means none in SID2 either, so equal */
	    if (!Sid1->SubAuthorityCount)
		return TRUE;

	    /* Now compare all the subauthority values BUT the last one */
	    for (i = 0; (i + 1) < Sid1->SubAuthorityCount; i++) {
		/* Does any mismatch? */
		if (Sid1->SubAuthority[i] != Sid2->SubAuthority[i]) {
		    /* Prefix doesn't match, fail */
		    return FALSE;
		}
	    }

	    /* Everything that should matches, does, return success */
	    return TRUE;
	}
    }

    /* Identifiers don't match, fail */
    return FALSE;
}

/*
 * @implemented
 */
NTAPI NTSTATUS RtlCopySidAndAttributesArray(IN ULONG Count,
					    IN PSID_AND_ATTRIBUTES Src,
					    IN ULONG SidAreaSize,
					    IN PSID_AND_ATTRIBUTES Dest,
					    IN PSID SidArea,
					    OUT PSID *RemainingSidArea,
					    OUT PULONG RemainingSidAreaSize)
{
    ULONG SidLength, i;

    /* Loop all the attributes */
    for (i = 0; i < Count; i++) {
	/* Make sure this SID can fit in the buffer */
	SidLength = RtlLengthSid(Src[i].Sid);
	if (SidLength > SidAreaSize)
	    return STATUS_BUFFER_TOO_SMALL;

	/* Consume remaining buffer space for this SID */
	SidAreaSize -= SidLength;

	/* Copy the SID and attributes */
	Dest[i].Sid = SidArea;
	Dest[i].Attributes = Src[i].Attributes;
	RtlCopySid(SidLength, SidArea, Src[i].Sid);

	/* Push the buffer area where the SID will reset */
	SidArea = (PSID) ((ULONG_PTR) SidArea + SidLength);
    }

    /* Return how much space is left, and where the buffer is at now */
    *RemainingSidArea = SidArea;
    *RemainingSidAreaSize = SidAreaSize;
    return STATUS_SUCCESS;
}

/*
 * @implemented
 */
NTAPI NTSTATUS RtlAllocateAndInitializeSid(IN PSID_IDENTIFIER_AUTHORITY IdentifierAuthority,
					   IN UCHAR SubAuthorityCount,
					   IN ULONG SubAuthority0,
					   IN ULONG SubAuthority1,
					   IN ULONG SubAuthority2,
					   IN ULONG SubAuthority3,
					   IN ULONG SubAuthority4,
					   IN ULONG SubAuthority5,
					   IN ULONG SubAuthority6,
					   IN ULONG SubAuthority7,
					   OUT PSID *Sid)
{
    PISID pSid;

    /* SIDs can only have up to 8 subauthorities */
    if (SubAuthorityCount > 8)
	return STATUS_INVALID_SID;

    /* Allocate memory to hold the SID */
    pSid = RtlpAllocateMemory(RtlLengthRequiredSid(SubAuthorityCount),
			      TAG_SID);
    if (!pSid)
	return STATUS_NO_MEMORY;

    /* Fill out the header */
    pSid->Revision = SID_REVISION;
    pSid->SubAuthorityCount = SubAuthorityCount;
    pSid->IdentifierAuthority = *IdentifierAuthority;

    /* Iteraratively drop into each successive lower count */
    switch (SubAuthorityCount) {
	/* And copy the needed subahority */
    case 8:
	pSid->SubAuthority[7] = SubAuthority7;
    case 7:
	pSid->SubAuthority[6] = SubAuthority6;
    case 6:
	pSid->SubAuthority[5] = SubAuthority5;
    case 5:
	pSid->SubAuthority[4] = SubAuthority4;
    case 4:
	pSid->SubAuthority[3] = SubAuthority3;
    case 3:
	pSid->SubAuthority[2] = SubAuthority2;
    case 2:
	pSid->SubAuthority[1] = SubAuthority1;
    case 1:
	pSid->SubAuthority[0] = SubAuthority0;
    default:
	break;
    }

    /* Return the allocated SID */
    *Sid = pSid;
    return STATUS_SUCCESS;
}

/*
 * @implemented
 */
NTAPI NTSTATUS RtlConvertSidToUnicodeString(IN PUNICODE_STRING String,
					    IN PSID Sid_,
					    IN BOOLEAN AllocateBuffer)
{
    WCHAR Buffer[256];
    PWSTR EndOfBuffer = &Buffer[sizeof(Buffer) / sizeof(WCHAR)];
    PWSTR wcs;
    SIZE_T Length;
    ULONG i;
    PISID Sid = Sid_;

    if (!RtlValidSid(Sid))
	return STATUS_INVALID_SID;

    wcs = Buffer;
    wcs += _snwprintf(wcs, sizeof(Buffer) / sizeof(WCHAR), L"S-1-");

    if ((Sid->IdentifierAuthority.Value[0] == 0) &&
	(Sid->IdentifierAuthority.Value[1] == 0)) {
	wcs += _snwprintf(wcs, EndOfBuffer - wcs,
			  L"%lu",
			  (ULONG) Sid->IdentifierAuthority.Value[2] << 24 |
			  (ULONG) Sid->IdentifierAuthority.Value[3] << 16 |
			  (ULONG) Sid->IdentifierAuthority.Value[4] << 8 |
			  (ULONG) Sid->IdentifierAuthority.Value[5]);
    } else {
	wcs += _snwprintf(wcs, EndOfBuffer - wcs,
			  L"0x%02hx%02hx%02hx%02hx%02hx%02hx",
			  Sid->IdentifierAuthority.Value[0],
			  Sid->IdentifierAuthority.Value[1],
			  Sid->IdentifierAuthority.Value[2],
			  Sid->IdentifierAuthority.Value[3],
			  Sid->IdentifierAuthority.Value[4],
			  Sid->IdentifierAuthority.Value[5]);
    }

    for (i = 0; i < Sid->SubAuthorityCount; i++) {
	wcs += _snwprintf(wcs, EndOfBuffer - wcs, L"-%u", Sid->SubAuthority[i]);
    }

    if (AllocateBuffer) {
	if (!RtlCreateUnicodeString(String, Buffer))
	    return STATUS_NO_MEMORY;
    } else {
	Length = (wcs - Buffer) * sizeof(WCHAR);

	if (Length > String->MaximumLength)
	    return STATUS_BUFFER_TOO_SMALL;

	String->Length = (USHORT) Length;
	RtlCopyMemory(String->Buffer, Buffer, Length);

	if (Length < String->MaximumLength) {
	    String->Buffer[Length / sizeof(WCHAR)] = UNICODE_NULL;
	}
    }

    return STATUS_SUCCESS;
}
