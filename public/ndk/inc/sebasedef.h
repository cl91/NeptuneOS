/* This file is imported by both the NT NDK and the Win32 SDK */

#pragma once

#include "ntbasedef.h"
#include "guiddef.h"

typedef PVOID PSECURITY_DESCRIPTOR;

typedef PVOID PACCESS_TOKEN;
typedef PVOID PSID;

typedef ULONG ACCESS_MASK, *PACCESS_MASK;
typedef ULONG SECURITY_INFORMATION, *PSECURITY_INFORMATION;

#ifndef SID_IDENTIFIER_AUTHORITY_DEFINED
#define SID_IDENTIFIER_AUTHORITY_DEFINED
typedef struct _SID_IDENTIFIER_AUTHORITY {
    UCHAR Value[6];
} SID_IDENTIFIER_AUTHORITY, *PSID_IDENTIFIER_AUTHORITY, *LPSID_IDENTIFIER_AUTHORITY;
#endif

typedef enum _WELL_KNOWN_SID_TYPE {
    WinNullSid = 0,
    WinWorldSid = 1,
    WinLocalSid = 2,
    WinCreatorOwnerSid = 3,
    WinCreatorGroupSid = 4,
    WinCreatorOwnerServerSid = 5,
    WinCreatorGroupServerSid = 6,
    WinNtAuthoritySid = 7,
    WinDialupSid = 8,
    WinNetworkSid = 9,
    WinBatchSid = 10,
    WinInteractiveSid = 11,
    WinServiceSid = 12,
    WinAnonymousSid = 13,
    WinProxySid = 14,
    WinEnterpriseControllersSid = 15,
    WinSelfSid = 16,
    WinAuthenticatedUserSid = 17,
    WinRestrictedCodeSid = 18,
    WinTerminalServerSid = 19,
    WinRemoteLogonIdSid = 20,
    WinLogonIdsSid = 21,
    WinLocalSystemSid = 22,
    WinLocalServiceSid = 23,
    WinNetworkServiceSid = 24,
    WinBuiltinDomainSid = 25,
    WinBuiltinAdministratorsSid = 26,
    WinBuiltinUsersSid = 27,
    WinBuiltinGuestsSid = 28,
    WinBuiltinPowerUsersSid = 29,
    WinBuiltinAccountOperatorsSid = 30,
    WinBuiltinSystemOperatorsSid = 31,
    WinBuiltinPrintOperatorsSid = 32,
    WinBuiltinBackupOperatorsSid = 33,
    WinBuiltinReplicatorSid = 34,
    WinBuiltinPreWindows2000CompatibleAccessSid = 35,
    WinBuiltinRemoteDesktopUsersSid = 36,
    WinBuiltinNetworkConfigurationOperatorsSid = 37,
    WinAccountAdministratorSid = 38,
    WinAccountGuestSid = 39,
    WinAccountKrbtgtSid = 40,
    WinAccountDomainAdminsSid = 41,
    WinAccountDomainUsersSid = 42,
    WinAccountDomainGuestsSid = 43,
    WinAccountComputersSid = 44,
    WinAccountControllersSid = 45,
    WinAccountCertAdminsSid = 46,
    WinAccountSchemaAdminsSid = 47,
    WinAccountEnterpriseAdminsSid = 48,
    WinAccountPolicyAdminsSid = 49,
    WinAccountRasAndIasServersSid = 50,
    WinNTLMAuthenticationSid = 51,
    WinDigestAuthenticationSid = 52,
    WinSChannelAuthenticationSid = 53,
    WinThisOrganizationSid = 54,
    WinOtherOrganizationSid = 55,
    WinBuiltinIncomingForestTrustBuildersSid = 56,
    WinBuiltinPerfMonitoringUsersSid = 57,
    WinBuiltinPerfLoggingUsersSid = 58,
    WinBuiltinAuthorizationAccessSid = 59,
    WinBuiltinTerminalServerLicenseServersSid = 60,
    WinBuiltinDCOMUsersSid = 61,
    WinBuiltinIUsersSid = 62,
    WinIUserSid = 63,
    WinBuiltinCryptoOperatorsSid = 64,
    WinUntrustedLabelSid = 65,
    WinLowLabelSid = 66,
    WinMediumLabelSid = 67,
    WinHighLabelSid = 68,
    WinSystemLabelSid = 69,
    WinWriteRestrictedCodeSid = 70,
    WinCreatorOwnerRightsSid = 71,
    WinCacheablePrincipalsGroupSid = 72,
    WinNonCacheablePrincipalsGroupSid = 73,
    WinEnterpriseReadonlyControllersSid = 74,
    WinAccountReadonlyControllersSid = 75,
    WinBuiltinEventLogReadersGroup = 76,
    WinNewEnterpriseReadonlyControllersSid = 77,
    WinBuiltinCertSvcDComAccessGroup = 78,
    WinMediumPlusLabelSid = 79,
    WinLocalLogonSid = 80,
    WinConsoleLogonSid = 81,
    WinThisOrganizationCertificateSid = 82,
    WinApplicationPackageAuthoritySid = 83,
    WinBuiltinAnyPackageSid = 84,
    WinCapabilityInternetClientSid = 85,
    WinCapabilityInternetClientServerSid = 86,
    WinCapabilityPrivateNetworkClientServerSid = 87,
    WinCapabilityPicturesLibrarySid = 88,
    WinCapabilityVideosLibrarySid = 89,
    WinCapabilityMusicLibrarySid = 90,
    WinCapabilityDocumentsLibrarySid = 91,
    WinCapabilitySharedUserCertificatesSid = 92,
    WinCapabilityEnterpriseAuthenticationSid = 93,
    WinCapabilityRemovableStorageSid = 94,
    WinBuiltinRDSRemoteAccessServersSid = 95,
    WinBuiltinRDSEndpointServersSid = 96,
    WinBuiltinRDSManagementServersSid = 97,
    WinUserModeDriversSid = 98,
    WinBuiltinHyperVAdminsSid = 99,
    WinAccountCloneableControllersSid = 100,
    WinBuiltinAccessControlAssistanceOperatorsSid = 101,
    WinBuiltinRemoteManagementUsersSid = 102,
    WinAuthenticationAuthorityAssertedSid = 103,
    WinAuthenticationServiceAssertedSid = 104,
    WinLocalAccountSid = 105,
    WinLocalAccountAndAdministratorSid = 106,
    WinAccountProtectedUsersSid = 107,
} WELL_KNOWN_SID_TYPE;

typedef struct _GENERIC_MAPPING {
    ACCESS_MASK GenericRead;
    ACCESS_MASK GenericWrite;
    ACCESS_MASK GenericExecute;
    ACCESS_MASK GenericAll;
} GENERIC_MAPPING, *PGENERIC_MAPPING;

typedef struct _ACL {
    UCHAR AclRevision;
    UCHAR Sbz1;
    USHORT AclSize;
    USHORT AceCount;
    USHORT Sbz2;
} ACL, *PACL;

#include "pshpack4.h"
typedef struct _LUID_AND_ATTRIBUTES {
    LUID Luid;
    ULONG Attributes;
} LUID_AND_ATTRIBUTES, *PLUID_AND_ATTRIBUTES;
#include "poppack.h"

typedef LUID_AND_ATTRIBUTES LUID_AND_ATTRIBUTES_ARRAY[ANYSIZE_ARRAY];
typedef LUID_AND_ATTRIBUTES_ARRAY *PLUID_AND_ATTRIBUTES_ARRAY;

/* Privilege sets */
#define PRIVILEGE_SET_ALL_NECESSARY (1)

typedef struct _PRIVILEGE_SET {
    ULONG PrivilegeCount;
    ULONG Control;
    LUID_AND_ATTRIBUTES Privilege[ANYSIZE_ARRAY];
} PRIVILEGE_SET, *PPRIVILEGE_SET;

typedef struct _OBJECT_TYPE_LIST {
    USHORT Level;
    USHORT Sbz;
    GUID *ObjectType;
} OBJECT_TYPE_LIST, *POBJECT_TYPE_LIST;

typedef struct _SID_AND_ATTRIBUTES {
    PSID Sid;
    ULONG Attributes;
} SID_AND_ATTRIBUTES, *PSID_AND_ATTRIBUTES;

typedef USHORT SECURITY_DESCRIPTOR_CONTROL, *PSECURITY_DESCRIPTOR_CONTROL;

typedef enum _SID_NAME_USE {
    SidTypeUser = 1,
    SidTypeGroup,
    SidTypeDomain,
    SidTypeAlias,
    SidTypeWellKnownGroup,
    SidTypeDeletedAccount,
    SidTypeInvalid,
    SidTypeUnknown,
    SidTypeComputer,
    SidTypeLabel
} SID_NAME_USE, *PSID_NAME_USE;

typedef struct _TOKEN_GROUPS {
    ULONG GroupCount;
#ifdef MIDL_PASS
    [size_is(GroupCount)] SID_AND_ATTRIBUTES Groups[*];
#else
    SID_AND_ATTRIBUTES Groups[ANYSIZE_ARRAY];
#endif
} TOKEN_GROUPS, *PTOKEN_GROUPS, *LPTOKEN_GROUPS;

typedef struct _TOKEN_PRIVILEGES {
    ULONG PrivilegeCount;
    LUID_AND_ATTRIBUTES Privileges[ANYSIZE_ARRAY];
} TOKEN_PRIVILEGES, *PTOKEN_PRIVILEGES, *LPTOKEN_PRIVILEGES;

typedef enum _TOKEN_TYPE {
    TokenPrimary = 1,
    TokenImpersonation
} TOKEN_TYPE, *PTOKEN_TYPE;

typedef enum _SECURITY_IMPERSONATION_LEVEL {
    SecurityAnonymous,
    SecurityIdentification,
    SecurityImpersonation,
    SecurityDelegation
} SECURITY_IMPERSONATION_LEVEL, *PSECURITY_IMPERSONATION_LEVEL;

typedef enum _TOKEN_INFORMATION_CLASS {
    TokenUser = 1,
    TokenGroups,
    TokenPrivileges,
    TokenOwner,
    TokenPrimaryGroup,
    TokenDefaultDacl,
    TokenSource,
    TokenType,
    TokenImpersonationLevel,
    TokenStatistics,
    TokenRestrictedSids,
    TokenSessionId,
    TokenGroupsAndPrivileges,
    TokenSessionReference,
    TokenSandBoxInert,
    TokenAuditPolicy,
    TokenOrigin,
    TokenElevationType,
    TokenLinkedToken,
    TokenElevation,
    TokenHasRestrictions,
    TokenAccessInformation,
    TokenVirtualizationAllowed,
    TokenVirtualizationEnabled,
    TokenIntegrityLevel,
    TokenUIAccess,
    TokenMandatoryPolicy,
    TokenLogonSid,
    TokenIsAppContainer,
    TokenCapabilities,
    TokenAppContainerSid,
    TokenAppContainerNumber,
    TokenUserClaimAttributes,
    TokenDeviceClaimAttributes,
    TokenRestrictedUserClaimAttributes,
    TokenRestrictedDeviceClaimAttributes,
    TokenDeviceGroups,
    TokenRestrictedDeviceGroups,
    TokenSecurityAttributes,
    TokenIsRestricted,
    MaxTokenInfoClass
} TOKEN_INFORMATION_CLASS, *PTOKEN_INFORMATION_CLASS;
