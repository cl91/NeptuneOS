#pragma once

#include <ntdll.h>

/*
 * Security descriptor internal helpers
 */
FORCEINLINE PSID SepGetGroupFromDescriptor(IN OUT PSECURITY_DESCRIPTOR Desc)
{
    PISECURITY_DESCRIPTOR Descriptor = (PISECURITY_DESCRIPTOR)Desc;
    PISECURITY_DESCRIPTOR_RELATIVE SdRel;

    if (Descriptor->Control & SE_SELF_RELATIVE) {
        SdRel = (PISECURITY_DESCRIPTOR_RELATIVE)Descriptor;
        if (!SdRel->Group)
            return NULL;
        return (PSID)((ULONG_PTR)Descriptor + SdRel->Group);
    } else {
        return Descriptor->Group;
    }
}

FORCEINLINE PSID SepGetOwnerFromDescriptor(IN OUT PSECURITY_DESCRIPTOR Desc)
{
    PISECURITY_DESCRIPTOR Descriptor = (PISECURITY_DESCRIPTOR)Desc;
    PISECURITY_DESCRIPTOR_RELATIVE SdRel;

    if (Descriptor->Control & SE_SELF_RELATIVE) {
        SdRel = (PISECURITY_DESCRIPTOR_RELATIVE)Descriptor;
        if (!SdRel->Owner) {
	    return NULL;
	}
        return (PSID)((ULONG_PTR)Descriptor + SdRel->Owner);
    } else {
        return Descriptor->Owner;
    }
}

FORCEINLINE PACL SepGetDaclFromDescriptor(IN OUT PSECURITY_DESCRIPTOR Desc)
{
    PISECURITY_DESCRIPTOR Descriptor = (PISECURITY_DESCRIPTOR)Desc;
    PISECURITY_DESCRIPTOR_RELATIVE SdRel;

    if (!(Descriptor->Control & SE_DACL_PRESENT))
        return NULL;

    if (Descriptor->Control & SE_SELF_RELATIVE) {
        SdRel = (PISECURITY_DESCRIPTOR_RELATIVE)Descriptor;
        if (!SdRel->Dacl)
            return NULL;
        return (PACL)((ULONG_PTR)Descriptor + SdRel->Dacl);
    } else {
        return Descriptor->Dacl;
    }
}

FORCEINLINE PACL SepGetSaclFromDescriptor(IN OUT PSECURITY_DESCRIPTOR Desc)
{
    PISECURITY_DESCRIPTOR Descriptor = (PISECURITY_DESCRIPTOR)Desc;
    PISECURITY_DESCRIPTOR_RELATIVE SdRel;

    if (!(Descriptor->Control & SE_SACL_PRESENT))
        return NULL;
    if (Descriptor->Control & SE_SELF_RELATIVE) {
        SdRel = (PISECURITY_DESCRIPTOR_RELATIVE)Descriptor;
        if (!SdRel->Sacl)
            return NULL;
        return (PACL)((ULONG_PTR)Descriptor + SdRel->Sacl);
    } else {
        return Descriptor->Sacl;
    }
}

VOID RtlpQuerySecurityDescriptor(IN PSECURITY_DESCRIPTOR SecurityDescriptor,
				 OUT PSID *Owner,
				 OUT PULONG OwnerSize,
				 OUT PSID *PrimaryGroup,
				 OUT PULONG PrimaryGroupSize,
				 OUT PACL *Dacl,
				 OUT PULONG DaclSize,
				 OUT PACL *Sacl,
				 OUT PULONG SaclSize);
