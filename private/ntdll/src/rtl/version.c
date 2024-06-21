/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS system libraries
 * PURPOSE:         Runtime code
 * FILE:            lib/rtl/version.c
 * PROGRAMERS:      Filip Navara
 *                  Hermes Belusca-Maito (hermes.belusca@sfr.fr)
 */

/* INCLUDES *****************************************************************/

#include <ntdll.h>

/* GLOBALS ******************************************************************/

/* FUNCTIONS ****************************************************************/

static UCHAR RtlpVerGetCondition(IN ULONGLONG ConditionMask, IN ULONG TypeMask);

static BOOLEAN RtlpVerCompare(ULONG Left, ULONG Right, UCHAR Condition)
{
    switch (Condition) {
    case VER_EQUAL:
	return (Left == Right);
    case VER_GREATER:
	return (Left > Right);
    case VER_GREATER_EQUAL:
	return (Left >= Right);
    case VER_LESS:
	return (Left < Right);
    case VER_LESS_EQUAL:
	return (Left <= Right);
    default:
	break;
    }
    return FALSE;
}

/*
* @implemented
*/
NTAPI NTSTATUS RtlVerifyVersionInfo(IN PRTL_OSVERSIONINFOEX VersionInfo,
				    IN ULONG TypeMask, IN ULONGLONG ConditionMask)
{
    RTL_OSVERSIONINFOEX Version;
    BOOLEAN Comparison;
    BOOLEAN DoNextCheck;
    NTSTATUS Status;
    UCHAR Condition;

    /* FIXME:
        - Check the following special case on Windows (various versions):
          o lp->wSuiteMask == 0 and ver.wSuiteMask != 0 and VER_AND/VER_OR
          o lp->dwOSVersionInfoSize != sizeof(OSVERSIONINFOEX)
        - MSDN talks about some tests being impossible. Check what really happens.
     */

    Version.dwOSVersionInfoSize = sizeof(Version);

    Status = RtlGetVersion((PRTL_OSVERSIONINFO)&Version);
    if (Status != STATUS_SUCCESS) {
	return Status;
    }

    if (!TypeMask || !ConditionMask) {
	return STATUS_INVALID_PARAMETER;
    }

    if (TypeMask & VER_PRODUCT_TYPE) {
	Comparison = RtlpVerCompare(Version.wProductType, VersionInfo->wProductType,
				    RtlpVerGetCondition(ConditionMask, VER_PRODUCT_TYPE));
	if (!Comparison) {
	    return STATUS_REVISION_MISMATCH;
	}
    }

    if (TypeMask & VER_SUITENAME) {
	switch (RtlpVerGetCondition(ConditionMask, VER_SUITENAME)) {
	case VER_AND: {
	    if ((VersionInfo->wSuiteMask & Version.wSuiteMask) !=
		VersionInfo->wSuiteMask) {
		return STATUS_REVISION_MISMATCH;
	    }
	} break;

	case VER_OR: {
	    if (!(VersionInfo->wSuiteMask & Version.wSuiteMask) &&
		VersionInfo->wSuiteMask) {
		return STATUS_REVISION_MISMATCH;
	    }
	    break;
	}

	default: {
	    return STATUS_INVALID_PARAMETER;
	}
	}
    }

    if (TypeMask & VER_PLATFORMID) {
	Comparison = RtlpVerCompare(Version.dwPlatformId, VersionInfo->dwPlatformId,
				    RtlpVerGetCondition(ConditionMask, VER_PLATFORMID));
	if (!Comparison) {
	    return STATUS_REVISION_MISMATCH;
	}
    }

    if (TypeMask & VER_BUILDNUMBER) {
	Comparison = RtlpVerCompare(Version.dwBuildNumber, VersionInfo->dwBuildNumber,
				    RtlpVerGetCondition(ConditionMask, VER_BUILDNUMBER));
	if (!Comparison) {
	    return STATUS_REVISION_MISMATCH;
	}
    }

    DoNextCheck = TRUE;
    Condition = VER_EQUAL;

    if (TypeMask & VER_MAJORVERSION) {
	Condition = RtlpVerGetCondition(ConditionMask, VER_MAJORVERSION);
	DoNextCheck = (VersionInfo->dwMajorVersion == Version.dwMajorVersion);
	Comparison = RtlpVerCompare(Version.dwMajorVersion, VersionInfo->dwMajorVersion,
				    Condition);

	if (!Comparison && !DoNextCheck) {
	    return STATUS_REVISION_MISMATCH;
	}
    }

    if (DoNextCheck) {
	if (TypeMask & VER_MINORVERSION) {
	    if (Condition == VER_EQUAL) {
		Condition = RtlpVerGetCondition(ConditionMask, VER_MINORVERSION);
	    }

	    DoNextCheck = (VersionInfo->dwMinorVersion == Version.dwMinorVersion);
	    Comparison = RtlpVerCompare(Version.dwMinorVersion,
					VersionInfo->dwMinorVersion, Condition);

	    if (!Comparison && !DoNextCheck) {
		return STATUS_REVISION_MISMATCH;
	    }
	}

	if (DoNextCheck && (TypeMask & VER_SERVICEPACKMAJOR)) {
	    if (Condition == VER_EQUAL) {
		Condition = RtlpVerGetCondition(ConditionMask, VER_SERVICEPACKMAJOR);
	    }

	    DoNextCheck = (VersionInfo->wServicePackMajor == Version.wServicePackMajor);
	    Comparison = RtlpVerCompare(Version.wServicePackMajor,
					VersionInfo->wServicePackMajor, Condition);

	    if (!Comparison && !DoNextCheck) {
		return STATUS_REVISION_MISMATCH;
	    }

	    if (DoNextCheck && (TypeMask & VER_SERVICEPACKMINOR)) {
		if (Condition == VER_EQUAL) {
		    Condition = RtlpVerGetCondition(ConditionMask, VER_SERVICEPACKMINOR);
		}

		Comparison = RtlpVerCompare(Version.wServicePackMinor,
					    VersionInfo->wServicePackMinor, Condition);

		if (!Comparison) {
		    return STATUS_REVISION_MISMATCH;
		}
	    }
	}
    }

    return STATUS_SUCCESS;
}

static UCHAR RtlpVerGetCondition(IN ULONGLONG ConditionMask, IN ULONG TypeMask)
{
    UCHAR Condition = 0;

    if (TypeMask & VER_PRODUCT_TYPE)
	Condition |= ConditionMask >> (7 * VER_NUM_BITS_PER_CONDITION_MASK);
    else if (TypeMask & VER_SUITENAME)
	Condition |= ConditionMask >> (6 * VER_NUM_BITS_PER_CONDITION_MASK);
    else if (TypeMask & VER_PLATFORMID)
	Condition |= ConditionMask >> (3 * VER_NUM_BITS_PER_CONDITION_MASK);
    else if (TypeMask & VER_BUILDNUMBER)
	Condition |= ConditionMask >> (2 * VER_NUM_BITS_PER_CONDITION_MASK);
    /*
     * We choose here the lexicographical order on the 4D space
     * {(Major ; Minor ; SP Major ; SP Minor)} to select the
     * appropriate comparison operator.
     * Therefore the following 'else if' instructions must be in this order.
     */
    else if (TypeMask & VER_MAJORVERSION)
	Condition |= ConditionMask >> (1 * VER_NUM_BITS_PER_CONDITION_MASK);
    else if (TypeMask & VER_MINORVERSION)
	Condition |= ConditionMask >> (0 * VER_NUM_BITS_PER_CONDITION_MASK);
    else if (TypeMask & VER_SERVICEPACKMAJOR)
	Condition |= ConditionMask >> (5 * VER_NUM_BITS_PER_CONDITION_MASK);
    else if (TypeMask & VER_SERVICEPACKMINOR)
	Condition |= ConditionMask >> (4 * VER_NUM_BITS_PER_CONDITION_MASK);

    Condition &= VER_CONDITION_MASK;

    return Condition;
}

/*
 * @implemented
 */
NTAPI ULONGLONG VerSetConditionMask(IN ULONGLONG ConditionMask, IN ULONG TypeMask,
				    IN UCHAR Condition)
{
    ULONGLONG CondMask;

    if (TypeMask == 0)
	return ConditionMask;

    Condition &= VER_CONDITION_MASK;

    if (Condition == 0)
	return ConditionMask;

    CondMask = Condition;
    if (TypeMask & VER_PRODUCT_TYPE)
	ConditionMask |= CondMask << (7 * VER_NUM_BITS_PER_CONDITION_MASK);
    else if (TypeMask & VER_SUITENAME)
	ConditionMask |= CondMask << (6 * VER_NUM_BITS_PER_CONDITION_MASK);
    else if (TypeMask & VER_SERVICEPACKMAJOR)
	ConditionMask |= CondMask << (5 * VER_NUM_BITS_PER_CONDITION_MASK);
    else if (TypeMask & VER_SERVICEPACKMINOR)
	ConditionMask |= CondMask << (4 * VER_NUM_BITS_PER_CONDITION_MASK);
    else if (TypeMask & VER_PLATFORMID)
	ConditionMask |= CondMask << (3 * VER_NUM_BITS_PER_CONDITION_MASK);
    else if (TypeMask & VER_BUILDNUMBER)
	ConditionMask |= CondMask << (2 * VER_NUM_BITS_PER_CONDITION_MASK);
    else if (TypeMask & VER_MAJORVERSION)
	ConditionMask |= CondMask << (1 * VER_NUM_BITS_PER_CONDITION_MASK);
    else if (TypeMask & VER_MINORVERSION)
	ConditionMask |= CondMask << (0 * VER_NUM_BITS_PER_CONDITION_MASK);

    return ConditionMask;
}

/**********************************************************************
 * NAME                         EXPORTED
 *  RtlGetNtProductType
 *
 * DESCRIPTION
 *  Retrieves the OS product type.
 *
 * ARGUMENTS
 *  ProductType Pointer to the product type variable.
 *
 * RETURN VALUE
 *  TRUE if successful, otherwise FALSE
 *
 * NOTE
 *  ProductType can be one of the following values:
 *    1 Workstation (WinNT)
 *    2 Server (LanmanNT)
 *    3 Advanced Server (ServerNT)
 *
 * REVISIONS
 *  2000-08-10 ekohl
 *
 * @implemented
 */
NTAPI BOOLEAN RtlGetNtProductType(_Out_ PNT_PRODUCT_TYPE ProductType)
{
    *ProductType = SharedUserData->NtProductType;
    return TRUE;
}

/**********************************************************************
 * NAME                         EXPORTED
 *  RtlGetNtVersionNumbers
 *
 * DESCRIPTION
 *  Get the version numbers of the run time library.
 *
 * ARGUMENTS
 *  pMajorVersion [OUT] Destination for the Major version
 *  pMinorVersion [OUT] Destination for the Minor version
 *  pBuildNumber  [OUT] Destination for the Build version
 *
 * RETURN VALUE
 *  Nothing.
 *
 * NOTES
 *  - Introduced in Windows XP (NT 5.1)
 *  - Since this call didn't exist before XP, we report at least the version
 *    5.1. This fixes the loading of msvcrt.dll as released with XP Home,
 *    which fails in DLLMain() if the major version isn't 5.
 *
 * @implemented
 */
NTAPI VOID RtlGetNtVersionNumbers(OUT PULONG MajorVersion, OUT PULONG MinorVersion,
				  OUT PULONG BuildNumber)
{
    PPEB Peb = NtCurrentPeb();

    if (MajorVersion) {
	*MajorVersion = Peb->OSMajorVersion < 5 ? 5 : Peb->OSMajorVersion;
    }

    if (MinorVersion) {
	if ((Peb->OSMajorVersion < 5) ||
	    ((Peb->OSMajorVersion == 5) && (Peb->OSMinorVersion < 1)))
	    *MinorVersion = 1;
	else
	    *MinorVersion = Peb->OSMinorVersion;
    }

    if (BuildNumber) {
	/* Windows really does this! */
	*BuildNumber = (0xF0000000 | Peb->OSBuildNumber);
    }
}

/*
 * @implemented
 */
NTAPI NTSTATUS RtlGetVersion(IN OUT PRTL_OSVERSIONINFO VersionInformation)
{
    SIZE_T Length;
    PPEB Peb = NtCurrentPeb();

    if (VersionInformation->dwOSVersionInfoSize != sizeof(RTL_OSVERSIONINFO) &&
	VersionInformation->dwOSVersionInfoSize != sizeof(RTL_OSVERSIONINFOEX)) {
	return STATUS_INVALID_PARAMETER;
    }

    VersionInformation->dwMajorVersion = Peb->OSMajorVersion;
    VersionInformation->dwMinorVersion = Peb->OSMinorVersion;
    VersionInformation->dwBuildNumber = Peb->OSBuildNumber;
    VersionInformation->dwPlatformId = Peb->OSPlatformId;
    RtlZeroMemory(VersionInformation->szCSDVersion,
		  sizeof(VersionInformation->szCSDVersion));

    /* If we have a CSD version string, initialized by Application Compatibility... */
    if (Peb->CSDVersion.Length && Peb->CSDVersion.Buffer &&
	Peb->CSDVersion.Buffer[0] != UNICODE_NULL) {
	/* ... copy it... */
	Length = min(wcslen(Peb->CSDVersion.Buffer),
		     ARRAYSIZE(VersionInformation->szCSDVersion) - 1);
	wcsncpy_s(VersionInformation->szCSDVersion,
		  sizeof(VersionInformation->szCSDVersion),
		  Peb->CSDVersion.Buffer, Length);
    } else {
	/* ... otherwise we just null-terminate it */
	Length = 0;
    }

    /* Always null-terminate the user CSD version string */
    VersionInformation->szCSDVersion[Length] = UNICODE_NULL;

    if (VersionInformation->dwOSVersionInfoSize == sizeof(RTL_OSVERSIONINFOEX)) {
	PRTL_OSVERSIONINFOEX InfoEx = (PRTL_OSVERSIONINFOEX)VersionInformation;
	InfoEx->wServicePackMajor = 0;
	InfoEx->wServicePackMinor = 0;
	InfoEx->wSuiteMask = SharedUserData->SuiteMask & 0xFFFF;
	InfoEx->wProductType = SharedUserData->NtProductType;
	InfoEx->wReserved = 0;
    }

    return STATUS_SUCCESS;
}
