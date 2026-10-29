/*
 * COPYRIGHT:         See COPYING in the top level directory
 * PROJECT:           ReactOS system libraries
 * PURPOSE:           Security descriptor functions
 * FILE:              lib/rtl/sd.c
 * PROGRAMER:         David Welch <welch@cwcom.net>
 */

/* INCLUDES *****************************************************************/

#include "rtlp.h"
#include "sd.h"

/* PRIVATE FUNCTIONS **********************************************************/

static BOOLEAN RtlpValidateSDOffsetAndSize(IN ULONG Offset,
					   IN ULONG Length,
					   IN ULONG MinLength,
					   OUT PULONG MaxLength)
{
    /* Assume failure */
    *MaxLength = 0;

    /* Reject out of bounds lengths */
    if (Offset < sizeof(SECURITY_DESCRIPTOR_RELATIVE))
	return FALSE;
    if (Offset >= Length)
	return FALSE;

    /* Reject insufficient lengths */
    if ((Length - Offset) < MinLength)
	return FALSE;

    /* Reject unaligned offsets */
    if (ALIGN_DOWN(Offset, ULONG) != Offset)
	return FALSE;

    /* Return length that is safe to read */
    *MaxLength = Length - Offset;
    return TRUE;
}

/* PUBLIC FUNCTIONS ***********************************************************/

/*
 * @implemented
 */
NTAPI NTSTATUS RtlCreateSecurityDescriptor(IN PSECURITY_DESCRIPTOR SecurityDescriptor,
					   IN ULONG Revision)
{
    PISECURITY_DESCRIPTOR Sd = (PISECURITY_DESCRIPTOR)SecurityDescriptor;

    /* Fail on invalid revisions */
    if (Revision != SECURITY_DESCRIPTOR_REVISION)
	return STATUS_UNKNOWN_REVISION;

    /* Setup an empty SD */
    RtlZeroMemory(Sd, sizeof(*Sd));
    Sd->Revision = SECURITY_DESCRIPTOR_REVISION;

    /* All good */
    return STATUS_SUCCESS;
}

/*
 * @implemented
 */
NTAPI NTSTATUS
RtlCreateSecurityDescriptorRelative(IN PISECURITY_DESCRIPTOR_RELATIVE SecurityDescriptor,
				    IN ULONG Revision)
{
    /* Fail on invalid revisions */
    if (Revision != SECURITY_DESCRIPTOR_REVISION)
	return STATUS_UNKNOWN_REVISION;

    /* Setup an empty SD */
    RtlZeroMemory(SecurityDescriptor, sizeof(*SecurityDescriptor));
    SecurityDescriptor->Revision = SECURITY_DESCRIPTOR_REVISION;
    SecurityDescriptor->Control = SE_SELF_RELATIVE;

    /* All good */
    return STATUS_SUCCESS;
}

/*
 * @implemented
 */
NTAPI NTSTATUS RtlGetDaclSecurityDescriptor(IN PSECURITY_DESCRIPTOR SecurityDescriptor,
					    OUT PBOOLEAN DaclPresent,
					    OUT PACL *Dacl,
					    OUT PBOOLEAN DaclDefaulted)
{
    PISECURITY_DESCRIPTOR Sd = (PISECURITY_DESCRIPTOR)SecurityDescriptor;

    /* Fail on invalid revisions */
    if (Sd->Revision != SECURITY_DESCRIPTOR_REVISION)
	return STATUS_UNKNOWN_REVISION;

    /* Is there a DACL? */
    *DaclPresent = (Sd->Control & SE_DACL_PRESENT) == SE_DACL_PRESENT;
    if (*DaclPresent) {
	/* Yes, return it, and check if defaulted */
	*Dacl = SepGetDaclFromDescriptor(Sd);
	*DaclDefaulted = (Sd->Control & SE_DACL_DEFAULTED) == SE_DACL_DEFAULTED;
    }

    /* All good */
    return STATUS_SUCCESS;
}

/*
 * @implemented
 */
NTAPI NTSTATUS RtlGetSaclSecurityDescriptor(IN PSECURITY_DESCRIPTOR SecurityDescriptor,
					    OUT PBOOLEAN SaclPresent,
					    OUT PACL *Sacl,
					    OUT PBOOLEAN SaclDefaulted)
{
    PISECURITY_DESCRIPTOR Sd = (PISECURITY_DESCRIPTOR)SecurityDescriptor;

    /* Fail on invalid revisions */
    if (Sd->Revision != SECURITY_DESCRIPTOR_REVISION)
	return STATUS_UNKNOWN_REVISION;

    /* Is there a SACL? */
    *SaclPresent = (Sd->Control & SE_SACL_PRESENT) == SE_SACL_PRESENT;
    if (*SaclPresent) {
	/* Yes, return it, and check if defaulted */
	*Sacl = SepGetSaclFromDescriptor(Sd);
	*SaclDefaulted = (Sd->Control & SE_SACL_DEFAULTED) == SE_SACL_DEFAULTED;
    }

    /* All good */
    return STATUS_SUCCESS;
}

/*
 * @implemented
 */
NTAPI NTSTATUS RtlGetOwnerSecurityDescriptor(IN PSECURITY_DESCRIPTOR SecurityDescriptor,
					     OUT PSID *Owner,
					     OUT PBOOLEAN OwnerDefaulted)
{
    PISECURITY_DESCRIPTOR Sd = (PISECURITY_DESCRIPTOR)SecurityDescriptor;

    /* Fail on invalid revision */
    if (Sd->Revision != SECURITY_DESCRIPTOR_REVISION)
	return STATUS_UNKNOWN_REVISION;

    /* Get the owner and if defaulted */
    *Owner = SepGetOwnerFromDescriptor(Sd);
    *OwnerDefaulted = (Sd->Control & SE_OWNER_DEFAULTED) == SE_OWNER_DEFAULTED;

    /* All good */
    return STATUS_SUCCESS;
}

/*
 * @implemented
 */
NTAPI NTSTATUS RtlGetGroupSecurityDescriptor(IN PSECURITY_DESCRIPTOR SecurityDescriptor,
					     OUT PSID *Group,
					     OUT PBOOLEAN GroupDefaulted)
{
    PISECURITY_DESCRIPTOR Sd = (PISECURITY_DESCRIPTOR)SecurityDescriptor;

    /* Fail on invalid revision */
    if (Sd->Revision != SECURITY_DESCRIPTOR_REVISION)
	return STATUS_UNKNOWN_REVISION;

    /* Get the group and if defaulted */
    *Group = SepGetGroupFromDescriptor(Sd);
    *GroupDefaulted = (Sd->Control & SE_GROUP_DEFAULTED) == SE_GROUP_DEFAULTED;

    /* All good */
    return STATUS_SUCCESS;
}

/*
 * @implemented
 */
NTAPI NTSTATUS RtlSetDaclSecurityDescriptor(IN OUT PSECURITY_DESCRIPTOR SecurityDescriptor,
					    IN BOOLEAN DaclPresent,
					    IN PACL Dacl,
					    IN BOOLEAN DaclDefaulted)
{
    PISECURITY_DESCRIPTOR Sd = (PISECURITY_DESCRIPTOR)SecurityDescriptor;

    /* Fail on invalid revision */
    if (Sd->Revision != SECURITY_DESCRIPTOR_REVISION)
	return STATUS_UNKNOWN_REVISION;

    /* Fail on relative descriptors */
    if (Sd->Control & SE_SELF_RELATIVE)
	return STATUS_INVALID_SECURITY_DESCR;

    /* Is there a DACL? */
    if (!DaclPresent) {
	/* Caller is destroying the DACL, unset the flag and we're done */
	Sd->Control = Sd->Control & ~SE_DACL_PRESENT;
	return STATUS_SUCCESS;
    }

    /* Caller is setting a new DACL, set the pointer and flag */
    Sd->Dacl = Dacl;
    Sd->Control |= SE_DACL_PRESENT;

    /* Set if defaulted */
    Sd->Control &= ~SE_DACL_DEFAULTED;
    if (DaclDefaulted)
	Sd->Control |= SE_DACL_DEFAULTED;

    /* All good */
    return STATUS_SUCCESS;
}

/*
 * @implemented
 */
NTAPI NTSTATUS RtlSetSaclSecurityDescriptor(IN OUT PSECURITY_DESCRIPTOR SecurityDescriptor,
					    IN BOOLEAN SaclPresent,
					    IN PACL Sacl,
					    IN BOOLEAN SaclDefaulted)
{
    PISECURITY_DESCRIPTOR Sd = (PISECURITY_DESCRIPTOR)SecurityDescriptor;

    /* Fail on invalid revision */
    if (Sd->Revision != SECURITY_DESCRIPTOR_REVISION)
	return STATUS_UNKNOWN_REVISION;

    /* Fail on relative descriptors */
    if (Sd->Control & SE_SELF_RELATIVE)
	return STATUS_INVALID_SECURITY_DESCR;

    /* Is there a SACL? */
    if (!SaclPresent) {
	/* Caller is clearing the SACL, unset the flag and we're done */
	Sd->Control = Sd->Control & ~SE_SACL_PRESENT;
	return STATUS_SUCCESS;
    }

    /* Caller is setting a new SACL, set it and the flag */
    Sd->Sacl = Sacl;
    Sd->Control |= SE_SACL_PRESENT;

    /* Set if defaulted */
    Sd->Control &= ~SE_SACL_DEFAULTED;
    if (SaclDefaulted)
	Sd->Control |= SE_SACL_DEFAULTED;

    /* All good */
    return STATUS_SUCCESS;
}

/*
 * @implemented
 */
NTAPI NTSTATUS RtlSetOwnerSecurityDescriptor(IN OUT PSECURITY_DESCRIPTOR SecurityDescriptor,
					     IN PSID Owner,
					     IN BOOLEAN OwnerDefaulted)
{
    PISECURITY_DESCRIPTOR Sd = (PISECURITY_DESCRIPTOR)SecurityDescriptor;

    /* Fail on invalid revision */
    if (Sd->Revision != SECURITY_DESCRIPTOR_REVISION)
	return STATUS_UNKNOWN_REVISION;

    /* Fail on relative descriptors */
    if (Sd->Control & SE_SELF_RELATIVE)
	return STATUS_INVALID_SECURITY_DESCR;

    /* Owner being set or cleared */
    Sd->Owner = Owner;

    /* Set if defaulted */
    Sd->Control &= ~SE_OWNER_DEFAULTED;
    if (OwnerDefaulted)
	Sd->Control |= SE_OWNER_DEFAULTED;

    /* All good */
    return STATUS_SUCCESS;
}

/*
 * @implemented
 */
NTAPI NTSTATUS RtlSetGroupSecurityDescriptor(IN OUT PSECURITY_DESCRIPTOR SecurityDescriptor,
					     IN PSID Group,
					     IN BOOLEAN GroupDefaulted)
{
    PISECURITY_DESCRIPTOR Sd = (PISECURITY_DESCRIPTOR)SecurityDescriptor;

    /* Fail on invalid revision */
    if (Sd->Revision != SECURITY_DESCRIPTOR_REVISION)
	return STATUS_UNKNOWN_REVISION;

    /* Fail on relative descriptors */
    if (Sd->Control & SE_SELF_RELATIVE)
	return STATUS_INVALID_SECURITY_DESCR;

    /* Group being set or cleared */
    Sd->Group = Group;

    /* Set if defaulted */
    Sd->Control &= ~SE_GROUP_DEFAULTED;
    if (GroupDefaulted)
	Sd->Control |= SE_GROUP_DEFAULTED;

    /* All good */
    return STATUS_SUCCESS;
}

/*
 * @implemented
 */
NTAPI BOOLEAN RtlGetSecurityDescriptorRMControl(IN PSECURITY_DESCRIPTOR SecurityDescriptor,
						OUT PUCHAR RMControl)
{
    PISECURITY_DESCRIPTOR Sd = (PISECURITY_DESCRIPTOR)SecurityDescriptor;

    /* Check if there's no valid RM control */
    if (!(Sd->Control & SE_RM_CONTROL_VALID)) {
	/* Fail and return nothing */
	*RMControl = 0;
	return FALSE;
    }

    /* Return it, ironically the member is "should be zero" */
    *RMControl = Sd->Sbz1;
    return TRUE;
}

/*
 * @implemented
 */
NTAPI VOID RtlSetSecurityDescriptorRMControl(IN PSECURITY_DESCRIPTOR SecurityDescriptor,
					     IN PUCHAR RMControl)
{
    PISECURITY_DESCRIPTOR Sd = (PISECURITY_DESCRIPTOR)SecurityDescriptor;

    /* RM Control is being cleared or set */
    if (!RMControl) {
	/* Clear it */
	Sd->Control &= ~SE_RM_CONTROL_VALID;
	Sd->Sbz1 = 0;
    } else {
	/* Set it */
	Sd->Control |= SE_RM_CONTROL_VALID;
	Sd->Sbz1 = *RMControl;
    }
}

/*
 * @implemented
 */
NTAPI NTSTATUS RtlSetAttributesSecurityDescriptor(IN PSECURITY_DESCRIPTOR SecurityDescriptor,
						  IN SECURITY_DESCRIPTOR_CONTROL Control,
						  OUT PULONG Revision)
{
    PISECURITY_DESCRIPTOR Sd = (PISECURITY_DESCRIPTOR)SecurityDescriptor;

    /* Always return revision, even if invalid */
    *Revision = Sd->Revision;

    /* Fail on invalid revision */
    if (Sd->Revision != SECURITY_DESCRIPTOR_REVISION)
	return STATUS_UNKNOWN_REVISION;

    /* Mask out flags which are not attributes */
    Control &= SE_DACL_UNTRUSTED | SE_SERVER_SECURITY | SE_DACL_AUTO_INHERIT_REQ |
	SE_SACL_AUTO_INHERIT_REQ | SE_DACL_AUTO_INHERITED |
	SE_SACL_AUTO_INHERITED | SE_DACL_PROTECTED | SE_SACL_PROTECTED;

    /* Call the newer API */
    return RtlSetControlSecurityDescriptor(SecurityDescriptor, Control, Control);
}

/*
 * @implemented
 */
NTAPI NTSTATUS
RtlCopySecurityDescriptor(IN PSECURITY_DESCRIPTOR pSourceSecurityDescriptor,
			  OUT PSECURITY_DESCRIPTOR *pDestinationSecurityDescriptor)
{
    PSID Owner, Group;
    PACL Dacl, Sacl;
    DWORD OwnerLength, GroupLength, DaclLength, SaclLength, TotalLength;
    PISECURITY_DESCRIPTOR Sd = pSourceSecurityDescriptor;

    /* Get all the components */
    RtlpQuerySecurityDescriptor(Sd, &Owner, &OwnerLength, &Group, &GroupLength, &Dacl,
				&DaclLength, &Sacl, &SaclLength);

    /* Add up their lengths */
    TotalLength = sizeof(SECURITY_DESCRIPTOR_RELATIVE) + OwnerLength + GroupLength +
	DaclLength + SaclLength;

    /* Allocate a copy */
    *pDestinationSecurityDescriptor = RtlAllocateHeap(RtlGetProcessHeap(), 0,
						      TotalLength);
    if (*pDestinationSecurityDescriptor == NULL)
	return STATUS_NO_MEMORY;

    /* Copy the old in the new */
    RtlCopyMemory(*pDestinationSecurityDescriptor, Sd, TotalLength);

    /* All good */
    return STATUS_SUCCESS;
}

/*
 * @implemented
 */
NTAPI BOOLEAN RtlValidSecurityDescriptor(IN PSECURITY_DESCRIPTOR SecurityDescriptor)
{
    PISECURITY_DESCRIPTOR Sd = (PISECURITY_DESCRIPTOR)SecurityDescriptor;
    PSID Owner, Group;
    PACL Sacl, Dacl;

    __try {
	/* Fail on bad revisions */
	if (Sd->Revision != SECURITY_DESCRIPTOR_REVISION)
	    return FALSE;

	/* Owner SID must be valid if present */
	Owner = SepGetOwnerFromDescriptor(Sd);
	if ((Owner) && (!RtlValidSid(Owner)))
	    return FALSE;

	/* Group SID must be valid if present */
	Group = SepGetGroupFromDescriptor(Sd);
	if ((Group) && (!RtlValidSid(Group)))
	    return FALSE;

	/* DACL must be valid if present */
	Dacl = SepGetDaclFromDescriptor(Sd);
	if ((Dacl) && (!RtlValidAcl(Dacl)))
	    return FALSE;

	/* SACL must be valid if present */
	Sacl = SepGetSaclFromDescriptor(Sd);
	if ((Sacl) && (!RtlValidAcl(Sacl)))
	    return FALSE;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
	/* Access fault, bail out */
	return FALSE;
    }

    /* All good */
    return TRUE;
}

/*
 * @implemented
 */
NTAPI BOOLEAN
RtlValidRelativeSecurityDescriptor(IN PSECURITY_DESCRIPTOR SecurityDescriptorInput,
				   IN ULONG SecurityDescriptorLength,
				   IN SECURITY_INFORMATION RequiredInformation)
{
    PISECURITY_DESCRIPTOR_RELATIVE Sd = (PISECURITY_DESCRIPTOR_RELATIVE)
	SecurityDescriptorInput;
    PSID Owner, Group;
    PACL Dacl, Sacl;
    ULONG Length;

    /* Note that Windows allows no DACL/SACL even if RequiredInfo wants it */

    /* Do we have enough space, is the revision vaild, and is this SD relative? */
    if ((SecurityDescriptorLength < sizeof(SECURITY_DESCRIPTOR_RELATIVE)) ||
	(Sd->Revision != SECURITY_DESCRIPTOR_REVISION) ||
	!(Sd->Control & SE_SELF_RELATIVE)) {
	/* Nope, bail out */
	return FALSE;
    }

    /* Is there an owner? */
    if (Sd->Owner) {
	/* Try to access it */
	if (!RtlpValidateSDOffsetAndSize(Sd->Owner, SecurityDescriptorLength, sizeof(SID),
					 &Length)) {
	    /* It's beyond the buffer, fail */
	    return FALSE;
	}

	/* Read the owner, check if it's valid and if the buffer contains it */
	Owner = (PSID)((ULONG_PTR)Sd->Owner + (ULONG_PTR)Sd);
	if (!RtlValidSid(Owner) || (Length < RtlLengthSid(Owner)))
	    return FALSE;
    } else if (RequiredInformation & OWNER_SECURITY_INFORMATION) {
	/* No owner but the caller expects one, fail */
	return FALSE;
    }

    /* Is there a group? */
    if (Sd->Group) {
	/* Try to access it */
	if (!RtlpValidateSDOffsetAndSize(Sd->Group, SecurityDescriptorLength, sizeof(SID),
					 &Length)) {
	    /* It's beyond the buffer, fail */
	    return FALSE;
	}

	/* Read the group, check if it's valid and if the buffer contains it */
	Group = (PSID)((ULONG_PTR)Sd->Group + (ULONG_PTR)Sd);
	if (!RtlValidSid(Group) || (Length < RtlLengthSid(Group)))
	    return FALSE;
    } else if (RequiredInformation & GROUP_SECURITY_INFORMATION) {
	/* No group, but the caller expects one, fail */
	return FALSE;
    }

    /* Is there a DACL? */
    if ((Sd->Control & SE_DACL_PRESENT) == SE_DACL_PRESENT) {
	/* Try to access it */
	if (!RtlpValidateSDOffsetAndSize(Sd->Dacl, SecurityDescriptorLength, sizeof(ACL),
					 &Length)) {
	    /* It's beyond the buffer, fail */
	    return FALSE;
	}

	/* Read the DACL, check if it's valid and if the buffer contains it */
	Dacl = (PSID)((ULONG_PTR)Sd->Dacl + (ULONG_PTR)Sd);
	if (!(RtlValidAcl(Dacl)) || (Length < Dacl->AclSize))
	    return FALSE;
    }

    /* Is there a SACL? */
    if ((Sd->Control & SE_SACL_PRESENT) == SE_SACL_PRESENT) {
	/* Try to access it */
	if (!RtlpValidateSDOffsetAndSize(Sd->Sacl, SecurityDescriptorLength, sizeof(ACL),
					 &Length)) {
	    /* It's beyond the buffer, fail */
	    return FALSE;
	}

	/* Read the SACL, check if it's valid and if the buffer contains it */
	Sacl = (PSID)((ULONG_PTR)Sd->Sacl + (ULONG_PTR)Sd);
	if (!(RtlValidAcl(Sacl)) || (Length < Sacl->AclSize))
	    return FALSE;
    }

    /* All good */
    return TRUE;
}

/* EOF */
