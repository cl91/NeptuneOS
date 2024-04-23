#pragma once

#include <ntdef.h>
#include <ntstatus.h>

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

#ifndef SID_DEFINED
#define SID_DEFINED
typedef struct _SID {
    UCHAR Revision;
    UCHAR SubAuthorityCount;
    SID_IDENTIFIER_AUTHORITY IdentifierAuthority;
    ULONG SubAuthority[];
} SID, *PISID;
#endif

#define SID_REVISION                    1
#define SID_MAX_SUB_AUTHORITIES         15
#define SID_RECOMMENDED_SUB_AUTHORITIES 1

#define SECURITY_MAX_SID_SIZE			\
    (sizeof(SID) - sizeof(ULONG) +		\
     (SID_MAX_SUB_AUTHORITIES * sizeof(ULONG)))

#define DELETE                   (0x00010000L)
#define READ_CONTROL             (0x00020000L)
#define WRITE_DAC                (0x00040000L)
#define WRITE_OWNER              (0x00080000L)
#define SYNCHRONIZE              (0x00100000L)
#define STANDARD_RIGHTS_REQUIRED (0x000F0000L)
#define STANDARD_RIGHTS_READ     (READ_CONTROL)
#define STANDARD_RIGHTS_WRITE    (READ_CONTROL)
#define STANDARD_RIGHTS_EXECUTE  (READ_CONTROL)
#define STANDARD_RIGHTS_ALL      (0x001F0000L)
#define SPECIFIC_RIGHTS_ALL      (0x0000FFFFL)
#define ACCESS_SYSTEM_SECURITY   (0x01000000L)
#define MAXIMUM_ALLOWED          (0x02000000L)
#define GENERIC_READ             (0x80000000L)
#define GENERIC_WRITE            (0x40000000L)
#define GENERIC_EXECUTE          (0x20000000L)
#define GENERIC_ALL              (0x10000000L)

#define SE_MIN_WELL_KNOWN_PRIVILEGE         2
#define SE_CREATE_TOKEN_PRIVILEGE           2
#define SE_ASSIGNPRIMARYTOKEN_PRIVILEGE     3
#define SE_LOCK_MEMORY_PRIVILEGE            4
#define SE_INCREASE_QUOTA_PRIVILEGE         5
#define SE_MACHINE_ACCOUNT_PRIVILEGE        6
#define SE_TCB_PRIVILEGE                    7
#define SE_SECURITY_PRIVILEGE               8
#define SE_TAKE_OWNERSHIP_PRIVILEGE         9
#define SE_LOAD_DRIVER_PRIVILEGE            10
#define SE_SYSTEM_PROFILE_PRIVILEGE         11
#define SE_SYSTEMTIME_PRIVILEGE             12
#define SE_PROF_SINGLE_PROCESS_PRIVILEGE    13
#define SE_INC_BASE_PRIORITY_PRIVILEGE      14
#define SE_CREATE_PAGEFILE_PRIVILEGE        15
#define SE_CREATE_PERMANENT_PRIVILEGE       16
#define SE_BACKUP_PRIVILEGE                 17
#define SE_RESTORE_PRIVILEGE                18
#define SE_SHUTDOWN_PRIVILEGE               19
#define SE_DEBUG_PRIVILEGE                  20
#define SE_AUDIT_PRIVILEGE                  21
#define SE_SYSTEM_ENVIRONMENT_PRIVILEGE     22
#define SE_CHANGE_NOTIFY_PRIVILEGE          23
#define SE_REMOTE_SHUTDOWN_PRIVILEGE        24
#define SE_UNDOCK_PRIVILEGE                 25
#define SE_SYNC_AGENT_PRIVILEGE             26
#define SE_ENABLE_DELEGATION_PRIVILEGE      27
#define SE_MANAGE_VOLUME_PRIVILEGE          28
#define SE_IMPERSONATE_PRIVILEGE            29
#define SE_CREATE_GLOBAL_PRIVILEGE          30
#define SE_TRUSTED_CREDMAN_ACCESS_PRIVILEGE 31
#define SE_RELABEL_PRIVILEGE                32
#define SE_INC_WORKING_SET_PRIVILEGE        33
#define SE_TIME_ZONE_PRIVILEGE              34
#define SE_CREATE_SYMBOLIC_LINK_PRIVILEGE   35
#define SE_MAX_WELL_KNOWN_PRIVILEGE         SE_CREATE_SYMBOLIC_LINK_PRIVILEGE

#define TOKEN_ASSIGN_PRIMARY    (0x0001)
#define TOKEN_DUPLICATE         (0x0002)
#define TOKEN_IMPERSONATE       (0x0004)
#define TOKEN_QUERY             (0x0008)
#define TOKEN_QUERY_SOURCE      (0x0010)
#define TOKEN_ADJUST_PRIVILEGES (0x0020)
#define TOKEN_ADJUST_GROUPS     (0x0040)
#define TOKEN_ADJUST_DEFAULT    (0x0080)
#define TOKEN_ADJUST_SESSIONID  (0x0100)

#define TOKEN_ALL_ACCESS_P (STANDARD_RIGHTS_REQUIRED |	\
                            TOKEN_ASSIGN_PRIMARY     |	\
                            TOKEN_DUPLICATE          |	\
                            TOKEN_IMPERSONATE        |	\
                            TOKEN_QUERY              |	\
                            TOKEN_QUERY_SOURCE       |	\
                            TOKEN_ADJUST_PRIVILEGES  |	\
                            TOKEN_ADJUST_GROUPS      |	\
                            TOKEN_ADJUST_DEFAULT)

#define TOKEN_ALL_ACCESS (TOKEN_ALL_ACCESS_P | TOKEN_ADJUST_SESSIONID)

#define TOKEN_READ (STANDARD_RIGHTS_READ | TOKEN_QUERY)

#define TOKEN_WRITE (STANDARD_RIGHTS_WRITE   |	\
                     TOKEN_ADJUST_PRIVILEGES |	\
                     TOKEN_ADJUST_GROUPS     |	\
                     TOKEN_ADJUST_DEFAULT)

#define TOKEN_EXECUTE (STANDARD_RIGHTS_EXECUTE)

typedef enum _TOKEN_TYPE {
    TokenPrimary = 1,
    TokenImpersonation
} TOKEN_TYPE, *PTOKEN_TYPE;

typedef struct _GENERIC_MAPPING {
    ACCESS_MASK GenericRead;
    ACCESS_MASK GenericWrite;
    ACCESS_MASK GenericExecute;
    ACCESS_MASK GenericAll;
} GENERIC_MAPPING, *PGENERIC_MAPPING;

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

typedef struct _SID_AND_ATTRIBUTES {
    PSID Sid;
    ULONG Attributes;
} SID_AND_ATTRIBUTES, *PSID_AND_ATTRIBUTES;

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

#ifndef _NTOSKRNL_

NTAPI NTSYSAPI NTSTATUS NtQueryInformationToken(IN HANDLE TokenHandle,
						IN TOKEN_INFORMATION_CLASS TokenInformationClass,
						OUT PVOID TokenInformation,
						IN ULONG TokenInformationLength,
						OUT PULONG ReturnLength);;

NTAPI NTSYSAPI NTSTATUS NtOpenProcessToken(IN HANDLE ProcessHandle,
					   IN ACCESS_MASK DesiredAccess,
					   OUT PHANDLE TokenHandle);

NTAPI NTSYSAPI NTSTATUS NtOpenProcessTokenEx(IN HANDLE ProcessHandle,
					     IN ACCESS_MASK DesiredAccess,
					     IN ULONG HandleAttributes,
					     OUT PHANDLE TokenHandle);

NTAPI NTSYSAPI NTSTATUS NtOpenThreadToken(IN HANDLE ThreadHandle,
					  IN ACCESS_MASK DesiredAccess,
					  IN BOOLEAN OpenAsSelf,
					  OUT PHANDLE TokenHandle);

NTAPI NTSYSAPI NTSTATUS NtOpenThreadTokenEx(IN HANDLE ThreadHandle,
					    IN ACCESS_MASK DesiredAccess,
					    IN BOOLEAN OpenAsSelf,
					    IN ULONG HandleAttributes,
					    OUT PHANDLE TokenHandle);

#endif
