#include "sd.h"

/*
 * @implemented
 */
NTAPI ULONG RtlLengthSid(IN PSID Ptr)
{
    PISID Sid = Ptr;

    /* The offset to the last index + 1 (since it's a count) is the length */
    return (ULONG) FIELD_OFFSET(SID, SubAuthority[Sid->SubAuthorityCount]);
}

/*
 * @implemented
 */
NTAPI NTSTATUS RtlGetControlSecurityDescriptor(IN PSECURITY_DESCRIPTOR SecurityDescriptor,
					       OUT PSECURITY_DESCRIPTOR_CONTROL Control,
					       OUT PULONG Revision)
{
    PISECURITY_DESCRIPTOR Sd = (PISECURITY_DESCRIPTOR)SecurityDescriptor;

    /* Read current revision, even if invalid */
    *Revision = Sd->Revision;

    /* Fail on invalid revision */
    if (Sd->Revision != SECURITY_DESCRIPTOR_REVISION)
	return STATUS_UNKNOWN_REVISION;

    /* Read current control */
    *Control = Sd->Control;

    /* All good */
    return STATUS_SUCCESS;
}

/*
 * @implemented
 */
NTAPI NTSTATUS
RtlSetControlSecurityDescriptor(IN PSECURITY_DESCRIPTOR SecurityDescriptor,
				IN SECURITY_DESCRIPTOR_CONTROL ControlBitsOfInterest,
				IN SECURITY_DESCRIPTOR_CONTROL ControlBitsToSet)
{
    PISECURITY_DESCRIPTOR Sd = (PISECURITY_DESCRIPTOR)SecurityDescriptor;

    /* Check for invalid bits */
    if ((ControlBitsOfInterest &
	 ~(SE_DACL_UNTRUSTED | SE_SERVER_SECURITY | SE_DACL_AUTO_INHERIT_REQ |
	   SE_SACL_AUTO_INHERIT_REQ | SE_DACL_AUTO_INHERITED | SE_SACL_AUTO_INHERITED |
	   SE_DACL_PROTECTED | SE_SACL_PROTECTED)) ||
	(ControlBitsToSet & ~ControlBitsOfInterest)) {
	/* Fail */
	return STATUS_INVALID_PARAMETER;
    }

    /* Zero the 'bits of interest' */
    Sd->Control &= ~ControlBitsOfInterest;

    /* Set the 'bits to set' */
    Sd->Control |= (ControlBitsToSet & ControlBitsOfInterest);

    /* All good */
    return STATUS_SUCCESS;
}

VOID RtlpQuerySecurityDescriptor(IN PSECURITY_DESCRIPTOR SecurityDescriptor,
				 OUT PSID *Owner,
				 OUT PULONG OwnerSize,
				 OUT PSID *PrimaryGroup,
				 OUT PULONG PrimaryGroupSize,
				 OUT PACL *Dacl,
				 OUT PULONG DaclSize,
				 OUT PACL *Sacl,
				 OUT PULONG SaclSize)
{
    /* Get the owner */
    *Owner = SepGetOwnerFromDescriptor(SecurityDescriptor);
    if (*Owner) {
	/* There's an owner, so align the size */
	*OwnerSize = ROUND_UP(RtlLengthSid(*Owner), sizeof(ULONG));
    } else {
	/* No owner, no size */
	*OwnerSize = 0;
    }

    /* Get the group */
    *PrimaryGroup = SepGetGroupFromDescriptor(SecurityDescriptor);
    if (*PrimaryGroup) {
	/* There's a group, so align the size */
	*PrimaryGroupSize = ROUND_UP(RtlLengthSid(*PrimaryGroup), sizeof(ULONG));
    } else {
	/* No group, no size */
	*PrimaryGroupSize = 0;
    }

    /* Get the DACL */
    *Dacl = SepGetDaclFromDescriptor(SecurityDescriptor);
    if (*Dacl) {
	/* There's a DACL, align the size */
	*DaclSize = ROUND_UP((*Dacl)->AclSize, sizeof(ULONG));
    } else {
	/* No DACL, no size */
	*DaclSize = 0;
    }

    /* Get the SACL */
    *Sacl = SepGetSaclFromDescriptor(SecurityDescriptor);
    if (*Sacl) {
	/* There's a SACL, align the size */
	*SaclSize = ROUND_UP((*Sacl)->AclSize, sizeof(ULONG));
    } else {
	/* No SACL, no size */
	*SaclSize = 0;
    }
}

/*
 * @implemented
 */
NTAPI NTSTATUS
RtlAbsoluteToSelfRelativeSD(IN PSECURITY_DESCRIPTOR AbsoluteSecurityDescriptor,
			    IN OUT PSECURITY_DESCRIPTOR SelfRelativeSecurityDescriptor,
			    IN PULONG BufferLength)
{
    PISECURITY_DESCRIPTOR Sd = (PISECURITY_DESCRIPTOR)AbsoluteSecurityDescriptor;

    /* Can't already be relative */
    if (Sd->Control & SE_SELF_RELATIVE)
	return STATUS_BAD_DESCRIPTOR_FORMAT;

    /* Call the other API */
    return RtlMakeSelfRelativeSD(AbsoluteSecurityDescriptor,
				 SelfRelativeSecurityDescriptor, BufferLength);
}

/*
 * @implemented
 */
NTAPI NTSTATUS RtlMakeSelfRelativeSD(IN PSECURITY_DESCRIPTOR SecurityDescriptor,
				     OUT PSECURITY_DESCRIPTOR SelfRelativeSD,
				     IN OUT PULONG BufferLength)
{
    PSID Owner, Group;
    PACL Sacl, Dacl;
    ULONG OwnerLength, GroupLength, SaclLength, DaclLength, TotalLength;
    ULONG_PTR Current;
    PISECURITY_DESCRIPTOR_RELATIVE RelSd = (PISECURITY_DESCRIPTOR_RELATIVE)SelfRelativeSD;

    /* Query all components */
    RtlpQuerySecurityDescriptor(SecurityDescriptor, &Owner, &OwnerLength, &Group,
				&GroupLength, &Dacl, &DaclLength, &Sacl, &SaclLength);

    /* Calculate final length */
    TotalLength = sizeof(SECURITY_DESCRIPTOR_RELATIVE) + OwnerLength + GroupLength +
	SaclLength + DaclLength;

    /* Is there enough space? */
    if (*BufferLength < TotalLength) {
	/* Nope, return how much is needed */
	*BufferLength = TotalLength;
	return STATUS_BUFFER_TOO_SMALL;
    }

    /* Start fresh */
    RtlZeroMemory(RelSd, TotalLength);

    /* Copy the header fields */
    RtlCopyMemory(RelSd, SecurityDescriptor,
		  FIELD_OFFSET(SECURITY_DESCRIPTOR_RELATIVE, Owner));

    /* Set the current copy pointer */
    Current = (ULONG_PTR)(RelSd + 1);

    /* Is there a SACL? */
    if (SaclLength) {
	/* Copy it */
	RtlCopyMemory((PVOID)Current, Sacl, SaclLength);
	RelSd->Sacl = (ULONG_PTR)Current - (ULONG_PTR)RelSd;
	Current += SaclLength;
    }

    /* Is there a DACL? */
    if (DaclLength) {
	/* Copy it */
	RtlCopyMemory((PVOID)Current, Dacl, DaclLength);
	RelSd->Dacl = (ULONG_PTR)Current - (ULONG_PTR)RelSd;
	Current += DaclLength;
    }

    /* Is there an owner? */
    if (OwnerLength) {
	/* Copy it */
	RtlCopyMemory((PVOID)Current, Owner, OwnerLength);
	RelSd->Owner = (ULONG_PTR)Current - (ULONG_PTR)RelSd;
	Current += OwnerLength;
    }

    /* Is there a group? */
    if (GroupLength) {
	/* Copy it */
	RtlCopyMemory((PVOID)Current, Group, GroupLength);
	RelSd->Group = (ULONG_PTR)Current - (ULONG_PTR)RelSd;
    }

    /* Mark it as relative */
    RelSd->Control |= SE_SELF_RELATIVE;

    /* All good */
    return STATUS_SUCCESS;
}

/*
 * @implemented
 */
NTAPI NTSTATUS RtlSelfRelativeToAbsoluteSD(IN PSECURITY_DESCRIPTOR SelfRelativeSD,
					   OUT PSECURITY_DESCRIPTOR AbsoluteSD,
					   IN PULONG AbsoluteSDSize,
					   IN PACL Dacl,
					   IN PULONG DaclSize,
					   IN PACL Sacl,
					   IN PULONG SaclSize,
					   IN PSID Owner,
					   IN PULONG OwnerSize,
					   IN PSID PrimaryGroup,
					   IN PULONG PrimaryGroupSize)
{
    PISECURITY_DESCRIPTOR Sd = (PISECURITY_DESCRIPTOR)AbsoluteSD;
    PISECURITY_DESCRIPTOR RelSd = (PISECURITY_DESCRIPTOR)SelfRelativeSD;
    ULONG OwnerLength, GroupLength, DaclLength, SaclLength;
    PSID pOwner, pGroup;
    PACL pDacl, pSacl;

    /* Must be relative, otherwiise fail */
    if (!(RelSd->Control & SE_SELF_RELATIVE))
	return STATUS_BAD_DESCRIPTOR_FORMAT;

    /* Get all the components */
    RtlpQuerySecurityDescriptor(RelSd, &pOwner, &OwnerLength, &pGroup, &GroupLength,
				&pDacl, &DaclLength, &pSacl, &SaclLength);

    /* Fail if there's not enough space */
    if (!(Sd) || (sizeof(SECURITY_DESCRIPTOR) > *AbsoluteSDSize) ||
	(OwnerLength > *OwnerSize) || (GroupLength > *PrimaryGroupSize) ||
	(DaclLength > *DaclSize) || (SaclLength > *SaclSize)) {
	/* Return how much space is needed for each components */
	*AbsoluteSDSize = sizeof(SECURITY_DESCRIPTOR);
	*OwnerSize = OwnerLength;
	*PrimaryGroupSize = GroupLength;
	*DaclSize = DaclLength;
	*SaclSize = SaclLength;
	return STATUS_BUFFER_TOO_SMALL;
    }

    /* Copy the header fields */
    RtlMoveMemory(Sd, RelSd, sizeof(SECURITY_DESCRIPTOR_RELATIVE));

    /* Wipe out the pointers and the relative flag */
    Sd->Owner = NULL;
    Sd->Group = NULL;
    Sd->Sacl = NULL;
    Sd->Dacl = NULL;
    Sd->Control &= ~SE_SELF_RELATIVE;

    /* Is there an owner? */
    if (pOwner) {
	/* Copy it */
	RtlMoveMemory(Owner, pOwner, RtlLengthSid(pOwner));
	Sd->Owner = Owner;
    }

    /* Is there a group? */
    if (pGroup) {
	/* Copy it */
	RtlMoveMemory(PrimaryGroup, pGroup, RtlLengthSid(pGroup));
	Sd->Group = PrimaryGroup;
    }

    /* Is there a DACL? */
    if (pDacl) {
	/* Copy it */
	RtlMoveMemory(Dacl, pDacl, pDacl->AclSize);
	Sd->Dacl = Dacl;
    }

    /* Is there a SACL? */
    if (pSacl) {
	/* Copy it */
	RtlMoveMemory(Sacl, pSacl, pSacl->AclSize);
	Sd->Sacl = Sacl;
    }

    /* All good */
    return STATUS_SUCCESS;
}

/*
 * @implemented
 */
NTAPI NTSTATUS RtlSelfRelativeToAbsoluteSD2(IN OUT PSECURITY_DESCRIPTOR SelfRelativeSD,
					    OUT PULONG BufferSize)
{
    PISECURITY_DESCRIPTOR Sd = (PISECURITY_DESCRIPTOR)SelfRelativeSD;
    PISECURITY_DESCRIPTOR_RELATIVE RelSd = (PISECURITY_DESCRIPTOR_RELATIVE)SelfRelativeSD;
    PVOID DataStart, DataEnd;
    LONG MoveDelta;
    ULONG DataSize, OwnerLength, GroupLength, DaclLength, SaclLength;
    PSID pOwner, pGroup;
    PACL pDacl, pSacl;

    /* Need input */
    if (!RelSd)
	return STATUS_INVALID_PARAMETER_1;

    /* Need to know how much space we have */
    if (!BufferSize)
	return STATUS_INVALID_PARAMETER_2;

    /* Input must be relative */
    if (!(RelSd->Control & SE_SELF_RELATIVE))
	return STATUS_BAD_DESCRIPTOR_FORMAT;

    /* Query all the component sizes */
    RtlpQuerySecurityDescriptor(Sd, &pOwner, &OwnerLength, &pGroup, &GroupLength, &pDacl,
				&DaclLength, &pSacl, &SaclLength);

    /*
     * Check if there's a difference in structure layout between relatiev and
     * absolute descriptors. On 32-bit, there won't be, since an offset is the
     * same size as a pointer (32-bit), but on 64-bit, the offsets remain 32-bit
     * as they are not SIZE_T, but ULONG, while the pointers now become 64-bit
     * and thus the structure is different */
    MoveDelta = sizeof(SECURITY_DESCRIPTOR) - sizeof(SECURITY_DESCRIPTOR_RELATIVE);
    if (!MoveDelta) {
	/* So on 32-bit, simply clear the flag... */
	Sd->Control &= ~SE_SELF_RELATIVE;

	/* Ensure we're *really* on 32-bit */
	ASSERT(sizeof(Sd->Owner) == sizeof(RelSd->Owner));
	ASSERT(sizeof(Sd->Group) == sizeof(RelSd->Group));
	ASSERT(sizeof(Sd->Sacl) == sizeof(RelSd->Sacl));
	ASSERT(sizeof(Sd->Dacl) == sizeof(RelSd->Dacl));

	/* And simply set pointers where there used to be offsets */
	Sd->Owner = pOwner;
	Sd->Group = pGroup;
	Sd->Sacl = pSacl;
	Sd->Dacl = pDacl;
	return STATUS_SUCCESS;
    }

    /*
     * Calculate the start and end of the data area, we simply just move the
     * data by the difference between the size of the relative and absolute
     * security descriptor structure
     */
    DataStart = pOwner;
    DataEnd = (PVOID)((ULONG_PTR)pOwner + OwnerLength);

    /* Is there a group? */
    if (pGroup) {
	/* Is the group higher than where we started? */
	if (((ULONG_PTR)pGroup < (ULONG_PTR)DataStart) || !DataStart) {
	    /* Update the start pointer */
	    DataStart = pGroup;
	}

	/* Is the group beyond where we ended? */
	if (((ULONG_PTR)pGroup + GroupLength > (ULONG_PTR)DataEnd) || !DataEnd) {
	    /* Update the end pointer */
	    DataEnd = (PVOID)((ULONG_PTR)pGroup + GroupLength);
	}
    }

    /* Is there a DACL? */
    if (pDacl) {
	/* Is the DACL higher than where we started? */
	if (((ULONG_PTR)pDacl < (ULONG_PTR)DataStart) || !DataStart) {
	    /* Update the start pointer */
	    DataStart = pDacl;
	}

	/* Is the DACL beyond where we ended? */
	if (((ULONG_PTR)pDacl + DaclLength > (ULONG_PTR)DataEnd) || !DataEnd) {
	    /* Update the end pointer */
	    DataEnd = (PVOID)((ULONG_PTR)pDacl + DaclLength);
	}
    }

    /* Is there a SACL? */
    if (pSacl) {
	/* Is the SACL higher than where we started? */
	if (((ULONG_PTR)pSacl < (ULONG_PTR)DataStart) || !DataStart) {
	    /* Update the start pointer */
	    DataStart = pSacl;
	}

	/* Is the SACL beyond where we ended? */
	if (((ULONG_PTR)pSacl + SaclLength > (ULONG_PTR)DataEnd) || !DataEnd) {
	    /* Update the end pointer */
	    DataEnd = (PVOID)((ULONG_PTR)pSacl + SaclLength);
	}
    }

    /* Sanity check */
    ASSERT((ULONG_PTR)DataEnd >= (ULONG_PTR)DataStart);

    /* Now compute the difference between relative and absolute */
    DataSize = (ULONG)((ULONG_PTR)DataEnd - (ULONG_PTR)DataStart);

    /* Is the new buffer large enough for this difference? */
    if (*BufferSize < sizeof(SECURITY_DESCRIPTOR) + DataSize) {
	/* Nope, bail out */
	*BufferSize = sizeof(SECURITY_DESCRIPTOR) + DataSize;
	return STATUS_BUFFER_TOO_SMALL;
    }

    /* Is there anything actually to copy? */
    if (DataSize) {
	/*
	 * There must be at least one SID or ACL in the security descriptor!
	 * Also the data area must be located somewhere after the end of the
	 * SECURITY_DESCRIPTOR_RELATIVE structure
	 */
	ASSERT(DataStart != NULL);
	ASSERT((ULONG_PTR)DataStart >= (ULONG_PTR)(RelSd + 1));

	/* It's time to move the data */
	RtlMoveMemory((PVOID)(Sd + 1), DataStart, DataSize);
    }

    /* Is there an owner? */
    if (pOwner) {
	/* Set the pointer to the relative position */
	Sd->Owner = (PSID)((LONG_PTR)pOwner + MoveDelta);
    } else {
	/* No owner, clear the pointer */
	Sd->Owner = NULL;
    }

    /* Is there a group */
    if (pGroup) {
	/* Set the pointer to the relative position */
	Sd->Group = (PSID)((LONG_PTR)pGroup + MoveDelta);
    } else {
	/* No group, clear the pointer */
	Sd->Group = NULL;
    }

    /* Is there a SACL? */
    if (pSacl) {
	/* Set the pointer to the relative position */
	Sd->Sacl = (PACL)((LONG_PTR)pSacl + MoveDelta);
    } else {
	/* No SACL, clear the pointer */
	Sd->Sacl = NULL;
    }

    /* Is there a DACL? */
    if (pDacl) {
	/* Set the pointer to the relative position */
	Sd->Dacl = (PACL)((LONG_PTR)pDacl + MoveDelta);
    } else {
	/* No DACL, clear the pointer */
	Sd->Dacl = NULL;
    }

    /* Clear the self-relative flag */
    Sd->Control &= ~SE_SELF_RELATIVE;

    /* All good */
    return STATUS_SUCCESS;
}

/*
 * @implemented
 */
NTAPI ULONG RtlLengthSecurityDescriptor(IN PSECURITY_DESCRIPTOR SecurityDescriptor)
{
    PISECURITY_DESCRIPTOR Sd;
    PSID Owner, Group;
    PACL Sacl, Dacl;
    ULONG Length;

    /* Start with the initial length of the SD itself */
    Sd = (PISECURITY_DESCRIPTOR)SecurityDescriptor;
    if (Sd->Control & SE_SELF_RELATIVE) {
	Length = sizeof(SECURITY_DESCRIPTOR_RELATIVE);
    } else {
	Length = sizeof(SECURITY_DESCRIPTOR);
    }

    /* Add the length of the individual subcomponents */
    Owner = SepGetOwnerFromDescriptor(Sd);
    if (Owner)
	Length += ROUND_UP(RtlLengthSid(Owner), sizeof(ULONG));
    Group = SepGetGroupFromDescriptor(Sd);
    if (Group)
	Length += ROUND_UP(RtlLengthSid(Group), sizeof(ULONG));
    Dacl = SepGetDaclFromDescriptor(Sd);
    if (Dacl)
	Length += ROUND_UP(Dacl->AclSize, sizeof(ULONG));
    Sacl = SepGetSaclFromDescriptor(Sd);
    if (Sacl)
	Length += ROUND_UP(Sacl->AclSize, sizeof(ULONG));

    /* Return the final length */
    return Length;
}
