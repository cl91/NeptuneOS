#pragma once

#include <guiddef.h>
#include <ntioapi.h>

#define CM_PROB_NOT_CONFIGURED              0x00000001
#define CM_PROB_DEVLOADER_FAILED            0x00000002
#define CM_PROB_OUT_OF_MEMORY               0x00000003
#define CM_PROB_ENTRY_IS_WRONG_TYPE         0x00000004
#define CM_PROB_LACKED_ARBITRATOR           0x00000005
#define CM_PROB_BOOT_CONFIG_CONFLICT        0x00000006
#define CM_PROB_FAILED_FILTER               0x00000007
#define CM_PROB_DEVLOADER_NOT_FOUND         0x00000008
#define CM_PROB_INVALID_DATA                0x00000009
#define CM_PROB_FAILED_START                0x0000000A
#define CM_PROB_LIAR                        0x0000000B
#define CM_PROB_NORMAL_CONFLICT             0x0000000C
#define CM_PROB_NOT_VERIFIED                0x0000000D
#define CM_PROB_NEED_RESTART                0x0000000E
#define CM_PROB_REENUMERATION               0x0000000F
#define CM_PROB_PARTIAL_LOG_CONF            0x00000010
#define CM_PROB_UNKNOWN_RESOURCE            0x00000011
#define CM_PROB_REINSTALL                   0x00000012
#define CM_PROB_REGISTRY                    0x00000013
#define CM_PROB_VXDLDR                      0x00000014
#define CM_PROB_WILL_BE_REMOVED             0x00000015
#define CM_PROB_DISABLED                    0x00000016
#define CM_PROB_DEVLOADER_NOT_READY         0x00000017
#define CM_PROB_DEVICE_NOT_THERE            0x00000018
#define CM_PROB_MOVED                       0x00000019
#define CM_PROB_TOO_EARLY                   0x0000001A
#define CM_PROB_NO_VALID_LOG_CONF           0x0000001B
#define CM_PROB_FAILED_INSTALL              0x0000001C
#define CM_PROB_HARDWARE_DISABLED           0x0000001D
#define CM_PROB_CANT_SHARE_IRQ              0x0000001E
#define CM_PROB_FAILED_ADD                  0x0000001F
#define CM_PROB_DISABLED_SERVICE            0x00000020
#define CM_PROB_TRANSLATION_FAILED          0x00000021
#define CM_PROB_NO_SOFTCONFIG               0x00000022
#define CM_PROB_BIOS_TABLE                  0x00000023
#define CM_PROB_IRQ_TRANSLATION_FAILED      0x00000024
#define CM_PROB_FAILED_DRIVER_ENTRY         0x00000025
#define CM_PROB_DRIVER_FAILED_PRIOR_UNLOAD  0x00000026
#define CM_PROB_DRIVER_FAILED_LOAD          0x00000027
#define CM_PROB_DRIVER_SERVICE_KEY_INVALID  0x00000028
#define CM_PROB_LEGACY_SERVICE_NO_DEVICES   0x00000029
#define CM_PROB_DUPLICATE_DEVICE            0x0000002A
#define CM_PROB_FAILED_POST_START           0x0000002B
#define CM_PROB_HALTED                      0x0000002C
#define CM_PROB_PHANTOM                     0x0000002D
#define CM_PROB_SYSTEM_SHUTDOWN             0x0000002E
#define CM_PROB_HELD_FOR_EJECT              0x0000002F
#define CM_PROB_DRIVER_BLOCKED              0x00000030
#define CM_PROB_REGISTRY_TOO_LARGE          0x00000031
#define CM_PROB_SETPROPERTIES_FAILED        0x00000032
#define CM_PROB_WAITING_ON_DEPENDENCY       0x00000033
#define CM_PROB_UNSIGNED_DRIVER             0x00000034

#define NUM_CM_PROB_V1                      0x00000025
#define NUM_CM_PROB_V2                      0x00000032
#define NUM_CM_PROB_V3                      0x00000033
#define NUM_CM_PROB_V4                      0x00000034
#define NUM_CM_PROB_V5                      0x00000035

#if (NTDDI_VERSION >= NTDDI_WIN7)
#define NUM_CM_PROB NUM_CM_PROB_V5
#elif (NTDDI_VERSION >= NTDDI_WS08)
#define NUM_CM_PROB NUM_CM_PROB_V4
#elif (NTDDI_VERSION >= NTDDI_WS03)
#define NUM_CM_PROB NUM_CM_PROB_V3
#elif (NTDDI_VERSION >= NTDDI_WINXP)
#define NUM_CM_PROB NUM_CM_PROB_V2
#elif (NTDDI_VERSION >= WIN2K)
#define NUM_CM_PROB NUM_CM_PROB_V1
#endif

#define LCPRI_FORCECONFIG                 0x00000000
#define LCPRI_BOOTCONFIG                  0x00000001
#define LCPRI_DESIRED                     0x00002000
#define LCPRI_NORMAL                      0x00003000
#define LCPRI_LASTBESTCONFIG              0x00003FFF
#define LCPRI_SUBOPTIMAL                  0x00005000
#define LCPRI_LASTSOFTCONFIG              0x00007FFF
#define LCPRI_RESTART                     0x00008000
#define LCPRI_REBOOT                      0x00009000
#define LCPRI_POWEROFF                    0x0000A000
#define LCPRI_HARDRECONFIG                0x0000C000
#define LCPRI_HARDWIRED                   0x0000E000
#define LCPRI_IMPOSSIBLE                  0x0000F000
#define LCPRI_DISABLED                    0x0000FFFF
#define MAX_LCPRI                         0x0000FFFF

#define DN_ROOT_ENUMERATED  0x00000001	/* Was enumerated by ROOT */
#define DN_DRIVER_LOADED    0x00000002	/* Has Register_Device_Driver */
#define DN_ENUM_LOADED      0x00000004	/* Has Register_Enumerator */
#define DN_STARTED          0x00000008	/* Is currently configured */
#define DN_MANUAL           0x00000010	/* Manually installed */
#define DN_NEED_TO_ENUM     0x00000020	/* May need reenumeration */
#define DN_NOT_FIRST_TIME   0x00000040	/* Has received a config (Win9x only) */
#define DN_HARDWARE_ENUM    0x00000080	/* Enum generates hardware ID */
#define DN_LIAR             0x00000100	/* Lied about can reconfig once (Win9x only) */
#define DN_HAS_MARK         0x00000200	/* Not CM_Create_DevNode lately (Win9x only) */
#define DN_HAS_PROBLEM      0x00000400	/* Need device installer */
#define DN_FILTERED         0x00000800	/* Is filtered */
#define DN_MOVED            0x00001000	/* Has been moved (Win9x only) */
#define DN_DISABLEABLE      0x00002000	/* Can be rebalanced */
#define DN_REMOVABLE        0x00004000	/* Can be removed */
#define DN_PRIVATE_PROBLEM  0x00008000	/* Has a private problem */
#define DN_MF_PARENT        0x00010000	/* Multi function parent */
#define DN_MF_CHILD         0x00020000	/* Multi function child */
#define DN_WILL_BE_REMOVED  0x00040000
#define DN_NOT_FIRST_TIMEE  0x00080000
#define DN_STOP_FREE_RES    0x00100000
#define DN_REBAL_CANDIDATE  0x00200000
#define DN_BAD_PARTIAL      0x00400000
#define DN_NT_ENUMERATOR    0x00800000
#define DN_NT_DRIVER        0x01000000
#define DN_NEEDS_LOCKING    0x02000000
#define DN_ARM_WAKEUP       0x04000000
#define DN_APM_ENUMERATOR   0x08000000
#define DN_APM_DRIVER       0x10000000
#define DN_SILENT_INSTALL   0x20000000
#define DN_NO_SHOW_IN_DM    0x40000000
#define DN_BOOT_LOG_PROB    0x80000000

#if (NTDDI_VERSION >= NTDDI_WINXP)

#define DN_NEED_RESTART DN_LIAR
#define DN_DRIVER_BLOCKED DN_NOT_FIRST_TIME
#define DN_LEGACY_DRIVER DN_MOVED
#define DN_CHILD_WITH_INVALID_ID DN_HAS_MARK

#elif (NTDDI_VERSION >= NTDDI_WIN2K)

#define DN_NEED_RESTART 0x00000100

#endif

#define DN_CHANGEABLE_FLAGS (DN_NOT_FIRST_TIME +	\
                             DN_HARDWARE_ENUM +		\
                             DN_HAS_MARK +		\
                             DN_DISABLEABLE +		\
                             DN_REMOVABLE +		\
                             DN_MF_CHILD +		\
                             DN_MF_PARENT +		\
                             DN_NOT_FIRST_TIMEE +	\
                             DN_STOP_FREE_RES +		\
                             DN_REBAL_CANDIDATE +	\
                             DN_NT_ENUMERATOR +		\
                             DN_NT_DRIVER +		\
                             DN_SILENT_INSTALL +	\
                             DN_NO_SHOW_IN_DM)

typedef enum _PNP_VETO_TYPE {
    PNP_VetoTypeUnknown,
    PNP_VetoLegacyDevice,
    PNP_VetoPendingClose,
    PNP_VetoWindowsApp,
    PNP_VetoWindowsService,
    PNP_VetoOutstandingOpen,
    PNP_VetoDevice,
    PNP_VetoDriver,
    PNP_VetoIllegalDeviceRequest,
    PNP_VetoInsufficientPower,
    PNP_VetoNonDisableable,
    PNP_VetoLegacyDriver
} PNP_VETO_TYPE, *PPNP_VETO_TYPE;

#define MAX_BUS_NAME 24

//
// PLUGPLAY_CONTROL_PROPERTY_DATA.Properties
//
#define PNP_PROPERTY_UI_NUMBER                        0
#define PNP_PROPERTY_PHYSICAL_DEVICE_OBJECT_NAME      1
#define PNP_PROPERTY_BUSTYPEGUID                      2
#define PNP_PROPERTY_LEGACYBUSTYPE                    3
#define PNP_PROPERTY_BUSNUMBER                        4
#define PNP_PROPERTY_POWER_DATA                       5
#define PNP_PROPERTY_REMOVAL_POLICY                   6
#define PNP_PROPERTY_REMOVAL_POLICY_OVERRIDE          7
#define PNP_PROPERTY_ADDRESS                          8
#define PNP_PROPERTY_ENUMERATOR_NAME                  9
#define PNP_PROPERTY_REMOVAL_POLICY_HARDWARE_DEFAULT 10
#define PNP_PROPERTY_INSTALL_STATE                   11
#define PNP_PROPERTY_LOCATION_PATHS                  12
#define PNP_PROPERTY_CONTAINERID                     13

//
// PLUGPLAY_CONTROL_RELATED_DEVICE_DATA.Relations
//
#define PNP_GET_PARENT_DEVICE           1
#define PNP_GET_CHILD_DEVICE            2
#define PNP_GET_SIBLING_DEVICE          3

//
// PLUGPLAY_CONTROL_STATUS_DATA.Operation
//
#define PNP_GET_DEVICE_STATUS           0
#define PNP_SET_DEVICE_STATUS           1
#define PNP_CLEAR_DEVICE_STATUS         2

//
// PLUGPLAY_CONTROL_DEVICE_RELATIONS_DATA.Relations
//
#define PNP_EJECT_RELATIONS             0
#define PNP_REMOVAL_RELATIONS           1
#define PNP_POWER_RELATIONS             2
#define PNP_BUS_RELATIONS               3


//
// Resource Type
//
#define CmResourceTypeNull                      0
#define CmResourceTypePort                      1
#define CmResourceTypeInterrupt                 2
#define CmResourceTypeMemory                    3
#define CmResourceTypeDma                       4
#define CmResourceTypeDeviceSpecific            5
#define CmResourceTypeBusNumber                 6
#define CmResourceTypeMemoryLarge               7
#define CmResourceTypeNonArbitrated             128
#define CmResourceTypeConfigData                128
#define CmResourceTypeDevicePrivate             129
#define CmResourceTypePcCardConfig              130
#define CmResourceTypeMfCardConfig              131


//
// Resource Descriptor Share Dispositions
//
typedef enum _CM_SHARE_DISPOSITION {
    CmResourceShareUndetermined,
    CmResourceShareDeviceExclusive,
    CmResourceShareDriverExclusive,
    CmResourceShareShared,
    CmResourceShareBusShared /* Resource is shared between the parent bus and child PDO */
} CM_SHARE_DISPOSITION;

//
// Port Resource Descriptor Flags
//
#define CM_RESOURCE_PORT_MEMORY                 0x0000
#define CM_RESOURCE_PORT_IO                     0x0001
#define CM_RESOURCE_PORT_10_BIT_DECODE          0x0004
#define CM_RESOURCE_PORT_12_BIT_DECODE          0x0008
#define CM_RESOURCE_PORT_16_BIT_DECODE          0x0010
#define CM_RESOURCE_PORT_POSITIVE_DECODE        0x0020
#define CM_RESOURCE_PORT_PASSIVE_DECODE         0x0040
#define CM_RESOURCE_PORT_WINDOW_DECODE          0x0080

//
// Memory Resource Descriptor Flags
//
#define CM_RESOURCE_MEMORY_READ_WRITE     0x0000
#define CM_RESOURCE_MEMORY_READ_ONLY      0x0001
#define CM_RESOURCE_MEMORY_WRITE_ONLY     0x0002
#define CM_RESOURCE_MEMORY_PREFETCHABLE   0x0004
#define CM_RESOURCE_MEMORY_COMBINEDWRITE  0x0008
#define CM_RESOURCE_MEMORY_24             0x0010
#define CM_RESOURCE_MEMORY_CACHEABLE      0x0020

//
// DMA Resource Descriptor Flags
//
#define CM_RESOURCE_DMA_8                 0x0000
#define CM_RESOURCE_DMA_16                0x0001
#define CM_RESOURCE_DMA_32                0x0002
#define CM_RESOURCE_DMA_8_AND_16          0x0004
#define CM_RESOURCE_DMA_BUS_MASTER        0x0008
#define CM_RESOURCE_DMA_TYPE_A            0x0010
#define CM_RESOURCE_DMA_TYPE_B            0x0020
#define CM_RESOURCE_DMA_TYPE_F            0x0040

//
// Interrupt Resource Descriptor Flags
//
#define CM_RESOURCE_INTERRUPT_LEVEL_SENSITIVE 0x0000
#define CM_RESOURCE_INTERRUPT_LATCHED         0x0001
#define CM_RESOURCE_INTERRUPT_MESSAGE         0x0002
#define CM_RESOURCE_INTERRUPT_POLICY_INCLUDED 0x0004
#define CM_RESOURCE_INTERRUPT_ALLOW_RESERVED_IDT    0x0008
#define CM_RESOURCE_INTERRUPT_SECONDARY_INTERRUPT   0x0010
#define CM_RESOURCE_INTERRUPT_WAKE_HINT             0x0020

#define CM_RESOURCE_INTERRUPT_LEVEL_LATCHED_BITS 0x0001

#define CM_RESOURCE_INTERRUPT_MESSAGE_TOKEN   ((ULONG)-2)

/* KEY_VALUE_Xxx.Type */
#define REG_NONE                           0
#define REG_SZ                             1
#define REG_EXPAND_SZ                      2
#define REG_BINARY                         3
#define REG_DWORD                          4
#define REG_DWORD_LITTLE_ENDIAN            4
#define REG_DWORD_BIG_ENDIAN               5
#define REG_LINK                           6
#define REG_MULTI_SZ                       7
#define REG_RESOURCE_LIST                  8
#define REG_FULL_RESOURCE_DESCRIPTOR       9
#define REG_RESOURCE_REQUIREMENTS_LIST     10
#define REG_QWORD                          11
#define REG_QWORD_LITTLE_ENDIAN            11

/* Registry Access Rights */
#define KEY_QUERY_VALUE         (0x0001)
#define KEY_SET_VALUE           (0x0002)
#define KEY_CREATE_SUB_KEY      (0x0004)
#define KEY_ENUMERATE_SUB_KEYS  (0x0008)
#define KEY_NOTIFY              (0x0010)
#define KEY_CREATE_LINK         (0x0020)
#define KEY_WOW64_32KEY         (0x0200)
#define KEY_WOW64_64KEY         (0x0100)
#define KEY_WOW64_RES           (0x0300)

#define KEY_READ                ((STANDARD_RIGHTS_READ       |	\
                                  KEY_QUERY_VALUE            |	\
                                  KEY_ENUMERATE_SUB_KEYS     |	\
                                  KEY_NOTIFY)			\
				 & (~SYNCHRONIZE))

#define KEY_WRITE               ((STANDARD_RIGHTS_WRITE      |	\
                                  KEY_SET_VALUE              |	\
                                  KEY_CREATE_SUB_KEY)		\
				 & (~SYNCHRONIZE))

#define KEY_EXECUTE             ((KEY_READ)		\
				 & (~SYNCHRONIZE))

#define KEY_ALL_ACCESS          ((STANDARD_RIGHTS_ALL        |	\
                                  KEY_QUERY_VALUE            |	\
                                  KEY_SET_VALUE              |	\
                                  KEY_CREATE_SUB_KEY         |	\
                                  KEY_ENUMERATE_SUB_KEYS     |	\
                                  KEY_NOTIFY                 |	\
                                  KEY_CREATE_LINK)		\
				 & (~SYNCHRONIZE))

/* Registry Open/Create Options */
#define REG_OPTION_RESERVED         (0x00000000L)
#define REG_OPTION_NON_VOLATILE     (0x00000000L)
#define REG_OPTION_VOLATILE         (0x00000001L)
#define REG_OPTION_CREATE_LINK      (0x00000002L)
#define REG_OPTION_BACKUP_RESTORE   (0x00000004L)
#define REG_OPTION_OPEN_LINK        (0x00000008L)

#define REG_LEGAL_OPTION			\
    (REG_OPTION_RESERVED            |		\
     REG_OPTION_NON_VOLATILE        |		\
     REG_OPTION_VOLATILE            |		\
     REG_OPTION_CREATE_LINK         |		\
     REG_OPTION_BACKUP_RESTORE      |		\
     REG_OPTION_OPEN_LINK)

#define REG_OPEN_LEGAL_OPTION			\
    (REG_OPTION_RESERVED            |		\
     REG_OPTION_BACKUP_RESTORE      |		\
     REG_OPTION_OPEN_LINK)

#define REG_STANDARD_FORMAT            1
#define REG_LATEST_FORMAT              2
#define REG_NO_COMPRESSION             4

/* Key creation/open disposition */
#define REG_CREATED_NEW_KEY         (0x00000001L)
#define REG_OPENED_EXISTING_KEY     (0x00000002L)

/* Key restore & hive load flags */
#define REG_WHOLE_HIVE_VOLATILE         (0x00000001L)
#define REG_REFRESH_HIVE                (0x00000002L)
#define REG_NO_LAZY_FLUSH               (0x00000004L)
#define REG_FORCE_RESTORE               (0x00000008L)
#define REG_APP_HIVE                    (0x00000010L)
#define REG_PROCESS_PRIVATE             (0x00000020L)
#define REG_START_JOURNAL               (0x00000040L)
#define REG_HIVE_EXACT_FILE_GROWTH      (0x00000080L)
#define REG_HIVE_NO_RM                  (0x00000100L)
#define REG_HIVE_SINGLE_LOG             (0x00000200L)
#define REG_BOOT_HIVE                   (0x00000400L)

/* Unload Flags */
#define REG_FORCE_UNLOAD            1

/* Notify Filter Values */
#define REG_NOTIFY_CHANGE_NAME          (0x00000001L)
#define REG_NOTIFY_CHANGE_ATTRIBUTES    (0x00000002L)
#define REG_NOTIFY_CHANGE_LAST_SET      (0x00000004L)
#define REG_NOTIFY_CHANGE_SECURITY      (0x00000008L)

#define REG_LEGAL_CHANGE_FILTER                 \
    (REG_NOTIFY_CHANGE_NAME          |		\
     REG_NOTIFY_CHANGE_ATTRIBUTES    |		\
     REG_NOTIFY_CHANGE_LAST_SET      |		\
     REG_NOTIFY_CHANGE_SECURITY)


//
// Information Classes for NtQueryKey
//
typedef enum _KEY_INFORMATION_CLASS {
    KeyBasicInformation,
    KeyNodeInformation,
    KeyFullInformation,
    KeyNameInformation,
    KeyCachedInformation,
    KeyFlagsInformation,
    KeyVirtualizationInformation,
    KeyHandleTagsInformation,
    MaxKeyInfoClass
} KEY_INFORMATION_CLASS;

typedef enum _KEY_VALUE_INFORMATION_CLASS {
    KeyValueBasicInformation,
    KeyValueFullInformation,
    KeyValuePartialInformation,
    KeyValueFullInformationAlign64,
    KeyValuePartialInformationAlign64,
    MaxKeyValueInfoClass
} KEY_VALUE_INFORMATION_CLASS;

typedef enum _KEY_SET_INFORMATION_CLASS {
    KeyWriteTimeInformation,
    KeyWow64FlagsInformation,
    KeyControlFlagsInformation,
    KeySetVirtualizationInformation,
    KeySetDebugInformation,
    KeySetHandleTagsInformation,
    MaxKeySetInfoClass
} KEY_SET_INFORMATION_CLASS;

//
// Plag and Play Classes
//
typedef enum _PLUGPLAY_CONTROL_CLASS {
    PlugPlayControlEnumerateDevice,
    PlugPlayControlRegisterNewDevice,
    PlugPlayControlDeregisterDevice,
    PlugPlayControlInitializeDevice,
    PlugPlayControlStartDevice,
    PlugPlayControlUnlockDevice,
    PlugPlayControlQueryAndRemoveDevice,
    PlugPlayControlUserResponse,
    PlugPlayControlGenerateLegacyDevice,
    PlugPlayControlGetInterfaceDeviceList,
    PlugPlayControlProperty,
    PlugPlayControlDeviceClassAssociation,
    PlugPlayControlGetRelatedDevice,
    PlugPlayControlGetInterfaceDeviceAlias,
    PlugPlayControlDeviceStatus,
    PlugPlayControlGetDeviceDepth,
    PlugPlayControlQueryDeviceRelations,
    PlugPlayControlTargetDeviceRelation,
    PlugPlayControlQueryConflictList,
    PlugPlayControlRetrieveDock,
    PlugPlayControlResetDevice,
    PlugPlayControlHaltDevice,
    PlugPlayControlGetBlockedDriverList,
    PlugPlayControlQueryHardwareIDs,
    PlugPlayControlQueryCompatibleIDs,
    MaxPlugPlayControl
} PLUGPLAY_CONTROL_CLASS;

typedef enum _PLUGPLAY_BUS_CLASS {
    SystemBus,
    PlugPlayVirtualBus,
    MaxPlugPlayBusClass
} PLUGPLAY_BUS_CLASS, *PPLUGPLAY_BUS_CLASS;

//
// Plag and Play Bus Types
//
typedef enum _PLUGPLAY_VIRTUAL_BUS_TYPE {
    Root,
    MaxPlugPlayVirtualBusType
} PLUGPLAY_VIRTUAL_BUS_TYPE, *PPLUGPLAY_VIRTUAL_BUS_TYPE;

//
// Plag and Play Event Categories
//
typedef enum _PLUGPLAY_EVENT_CATEGORY {
    HardwareProfileChangeEvent,
    TargetDeviceChangeEvent,
    DeviceClassChangeEvent,
    CustomDeviceEvent,
    DeviceInstallEvent,
    DeviceArrivalEvent,
    PowerEvent,
    VetoEvent,
    BlockedDriverEvent,
    MaxPlugEventCategory
} PLUGPLAY_EVENT_CATEGORY;

//
// Information Structures for NtQueryKeyInformation
//
typedef struct _KEY_WRITE_TIME_INFORMATION {
    LARGE_INTEGER LastWriteTime;
} KEY_WRITE_TIME_INFORMATION, *PKEY_WRITE_TIME_INFORMATION;

typedef struct _KEY_WOW64_FLAGS_INFORMATION {
    ULONG UserFlags;
} KEY_WOW64_FLAGS_INFORMATION, *PKEY_WOW64_FLAGS_INFORMATION;

typedef struct _KEY_USER_FLAGS_INFORMATION {
    ULONG UserFlags;
} KEY_USER_FLAGS_INFORMATION, *PKEY_USER_FLAGS_INFORMATION;

typedef struct _KEY_HANDLE_TAGS_INFORMATION {
    ULONG HandleTags;
} KEY_HANDLE_TAGS_INFORMATION, *PKEY_HANDLE_TAGS_INFORMATION;

typedef struct _KEY_CONTROL_FLAGS_INFORMATION {
    ULONG ControlFlags;
} KEY_CONTROL_FLAGS_INFORMATION, *PKEY_CONTROL_FLAGS_INFORMATION;

typedef struct _KEY_VIRTUALIZATION_INFORMATION {
    ULONG VirtualizationCandidate:1;
    ULONG VirtualizationEnabled:1;
    ULONG VirtualTarget:1;
    ULONG VirtualStore:1;
    ULONG VirtualSource:1;
    ULONG Reserved:27;
} KEY_VIRTUALIZATION_INFORMATION, *PKEY_VIRTUALIZATION_INFORMATION;

typedef struct _KEY_SET_VIRTUALIZATION_INFORMATION {
    ULONG VirtualTarget:1;
    ULONG VirtualStore:1;
    ULONG VirtualSource:1;
    ULONG Reserved:29;
} KEY_SET_VIRTUALIZATION_INFORMATION, *PKEY_SET_VIRTUALIZATION_INFORMATION;

//
// NtQueryKey Information
//
typedef struct _KEY_FULL_INFORMATION {
    LARGE_INTEGER LastWriteTime;
    ULONG TitleIndex;
    ULONG ClassOffset;
    ULONG ClassLength;
    ULONG SubKeys;
    ULONG MaxNameLen;
    ULONG MaxClassLen;
    ULONG Values;
    ULONG MaxValueNameLen;
    ULONG MaxValueDataLen;
    WCHAR Class[];
} KEY_FULL_INFORMATION, *PKEY_FULL_INFORMATION;

typedef struct _KEY_NAME_INFORMATION {
    ULONG NameLength;
    WCHAR Name[];
} KEY_NAME_INFORMATION, *PKEY_NAME_INFORMATION;

typedef struct _KEY_NODE_INFORMATION {
    LARGE_INTEGER LastWriteTime;
    ULONG TitleIndex;
    ULONG ClassOffset;
    ULONG ClassLength;
    ULONG NameLength;
    WCHAR Name[];
} KEY_NODE_INFORMATION, *PKEY_NODE_INFORMATION;

typedef struct _KEY_VALUE_ENTRY {
    PUNICODE_STRING ValueName;
    ULONG DataLength;
    ULONG DataOffset;
    ULONG Type;
} KEY_VALUE_ENTRY, *PKEY_VALUE_ENTRY;

typedef struct _KEY_VALUE_PARTIAL_INFORMATION {
    ULONG TitleIndex;
    ULONG Type;
    ULONG DataLength;
    UCHAR Data[];
} KEY_VALUE_PARTIAL_INFORMATION, *PKEY_VALUE_PARTIAL_INFORMATION;

typedef struct _KEY_VALUE_PARTIAL_INFORMATION_ALIGN64 {
    ULONG Type;
    ULONG DataLength;
    UCHAR Data[];
} KEY_VALUE_PARTIAL_INFORMATION_ALIGN64, *PKEY_VALUE_PARTIAL_INFORMATION_ALIGN64;

typedef struct _KEY_VALUE_BASIC_INFORMATION {
    ULONG TitleIndex;
    ULONG Type;
    ULONG NameLength;
    WCHAR Name[];
} KEY_VALUE_BASIC_INFORMATION, *PKEY_VALUE_BASIC_INFORMATION;

typedef struct _KEY_VALUE_FULL_INFORMATION {
    ULONG TitleIndex;
    ULONG Type;
    ULONG DataOffset;
    ULONG DataLength;
    ULONG NameLength;
    WCHAR Name[];
} KEY_VALUE_FULL_INFORMATION, *PKEY_VALUE_FULL_INFORMATION;

typedef struct _KEY_BASIC_INFORMATION {
    LARGE_INTEGER LastWriteTime;
    ULONG TitleIndex;
    ULONG NameLength;
    WCHAR Name[];
} KEY_BASIC_INFORMATION, *PKEY_BASIC_INFORMATION;

//
// Plug and Play Event Block
//
typedef struct _PLUGPLAY_EVENT_BLOCK {
    GUID EventGuid;
    PLUGPLAY_EVENT_CATEGORY EventCategory;
    PULONG Result;
    ULONG Flags;
    ULONG TotalSize;
    PVOID DeviceObject;
    union {
	struct {
	    GUID ClassGuid;
	    WCHAR SymbolicLinkName[ANYSIZE_ARRAY];
	} DeviceClass;
	struct {
	    WCHAR DeviceIds[1];
	} TargetDevice;
	struct {
	    WCHAR DeviceId[1];
	} InstallDevice;
	struct {
	    PVOID NotificationStructure;
	    WCHAR DeviceIds[ANYSIZE_ARRAY];
	} CustomNotification;
	struct {
	    PVOID Notification;
	} ProfileNotification;
	struct {
	    ULONG NotificationCode;
	    ULONG NotificationData;
	} PowerNotification;
	struct {
	    PNP_VETO_TYPE VetoType;
	    WCHAR DeviceIdVetoNameBuffer[ANYSIZE_ARRAY];
	} VetoNotification;
	struct {
	    GUID BlockedDriverGuid;
	} BlockedDriverNotification;
    };
} PLUGPLAY_EVENT_BLOCK, *PPLUGPLAY_EVENT_BLOCK;

//
// PNP Bus Query ID Type
//
typedef enum _BUS_QUERY_ID_TYPE {
    BusQueryDeviceID,
    BusQueryHardwareIDs,
    BusQueryCompatibleIDs,
    BusQueryInstanceID,
    BusQueryDeviceSerialNumber,
    BusQueryContainerID
} BUS_QUERY_ID_TYPE, *PBUS_QUERY_ID_TYPE;

typedef enum _DEVICE_TEXT_TYPE {
    DeviceTextDescription,
    DeviceTextLocationInformation
} DEVICE_TEXT_TYPE, *PDEVICE_TEXT_TYPE;

typedef enum _DEVICE_USAGE_NOTIFICATION_TYPE {
    DeviceUsageTypeUndefined,
    DeviceUsageTypePaging,
    DeviceUsageTypeHibernation,
    DeviceUsageTypeDumpFile,
    DeviceUsageTypeBoot,
    DeviceUsageTypePostDisplay,
    DeviceUsageTypeGuestAssigned,
} DEVICE_USAGE_NOTIFICATION_TYPE;

//
// PNP Query Device Relation Type
//
typedef enum _DEVICE_RELATION_TYPE {
    BusRelations,
    EjectionRelations,
    PowerRelations,
    RemovalRelations,
    TargetDeviceRelation,
    SingleBusRelations,
    TransportRelations
} DEVICE_RELATION_TYPE, *PDEVICE_RELATION_TYPE;

//
// Plug and Play Control Classes
//

// PlugPlayControlEnumerateDevice (0x00)
typedef struct _PLUGPLAY_CONTROL_ENUMERATE_DEVICE_DATA {
    UNICODE_STRING DeviceInstance;
    ULONG Flags;
} PLUGPLAY_CONTROL_ENUMERATE_DEVICE_DATA, *PPLUGPLAY_CONTROL_ENUMERATE_DEVICE_DATA;

// PlugPlayControlRegisterNewDevice (0x1)
// PlugPlayControlDeregisterDevice (0x2)
// PlugPlayControlInitializeDevice (0x3)
// PlugPlayControlStartDevice (0x4)
// PlugPlayControlUnlockDevice (0x5)
// PlugPlayControlResetDevice (0x14)
// PlugPlayControlHaltDevice (0x15)
typedef struct _PLUGPLAY_CONTROL_DEVICE_CONTROL_DATA {
    UNICODE_STRING DeviceInstance;
} PLUGPLAY_CONTROL_DEVICE_CONTROL_DATA, *PPLUGPLAY_CONTROL_DEVICE_CONTROL_DATA;

// PlugPlayControlQueryAndRemoveDevice (0x06)
typedef struct _PLUGPLAY_CONTROL_QUERY_REMOVE_DATA {
    UNICODE_STRING DeviceInstance;
    ULONG Flags;
    PNP_VETO_TYPE VetoType;
    PWSTR VetoName;
    ULONG NameLength;
} PLUGPLAY_CONTROL_QUERY_REMOVE_DATA, *PPLUGPLAY_CONTROL_QUERY_REMOVE_DATA;

// PlugPlayControlUserResponse (0x07)
typedef struct _PLUGPLAY_CONTROL_USER_RESPONSE_DATA {
    ULONG Unknown1;
    ULONG Unknown2;
    ULONG Unknown3;
    ULONG Unknown4;
} PLUGPLAY_CONTROL_USER_RESPONSE_DATA, *PPLUGPLAY_CONTROL_USER_RESPONSE_DATA;

// PlugPlayControlGetInterfaceDeviceList (0x09)
typedef struct _PLUGPLAY_CONTROL_INTERFACE_DEVICE_LIST_DATA {
    UNICODE_STRING DeviceInstance;
    LPGUID FilterGuid;
    ULONG Flags;
    PVOID Buffer;
    ULONG BufferSize;
} PLUGPLAY_CONTROL_INTERFACE_DEVICE_LIST_DATA, *PPLUGPLAY_CONTROL_INTERFACE_DEVICE_LIST_DATA;

// PlugPlayControlProperty (0x0A)
typedef struct _PLUGPLAY_CONTROL_PROPERTY_DATA {
    UNICODE_STRING DeviceInstance;
    ULONG Property;
    PVOID Buffer;
    ULONG BufferSize;
} PLUGPLAY_CONTROL_PROPERTY_DATA, *PPLUGPLAY_CONTROL_PROPERTY_DATA;

// PlugPlayControlDeviceClassAssociation (0x0B)
typedef struct _PLUGPLAY_CONTROL_CLASS_ASSOCIATION_DATA {
    UNICODE_STRING DeviceInstance;
    GUID *InterfaceGuid;
    UNICODE_STRING Reference;
    BOOLEAN Register;
    PWCHAR SymbolicLinkName;
    ULONG SymbolicLinkNameLength;
} PLUGPLAY_CONTROL_CLASS_ASSOCIATION_DATA, *PPLUGPLAY_CONTROL_CLASS_ASSOCIATION_DATA;

// PlugPlayControlGetRelatedDevice (0x0C)
typedef struct _PLUGPLAY_CONTROL_RELATED_DEVICE_DATA {
    UNICODE_STRING TargetDeviceInstance;
    ULONG Relation;
    PWCHAR RelatedDeviceInstance;
    ULONG RelatedDeviceInstanceLength;
} PLUGPLAY_CONTROL_RELATED_DEVICE_DATA, *PPLUGPLAY_CONTROL_RELATED_DEVICE_DATA;

// PlugPlayControlGetInterfaceDeviceAlias (0x0D)
typedef struct _PLUGPLAY_CONTROL_INTERFACE_ALIAS_DATA {
    UNICODE_STRING SymbolicLinkName;
    GUID *AliasInterfaceClassGuid;
    PWCHAR AliasSymbolicLinkName;
    ULONG AliasSymbolicLinkNameLength;
} PLUGPLAY_CONTROL_INTERFACE_ALIAS_DATA, *PPLUGPLAY_CONTROL_INTERFACE_ALIAS_DATA;

// PlugPlayControlDeviceStatus (0x0E)
typedef struct _PLUGPLAY_CONTOL_STATUS_DATA {
    UNICODE_STRING DeviceInstance;
    ULONG Operation;
    ULONG DeviceStatus;
    ULONG DeviceProblem;
} PLUGPLAY_CONTROL_STATUS_DATA, *PPLUGPLAY_CONTROL_STATUS_DATA;

// PlugPlayControlGetDeviceDepth (0x0F)
typedef struct _PLUGPLAY_CONTROL_DEPTH_DATA {
    UNICODE_STRING DeviceInstance;
    ULONG Depth;
} PLUGPLAY_CONTROL_DEPTH_DATA, *PPLUGPLAY_CONTROL_DEPTH_DATA;

// PlugPlayControlQueryDeviceRelations (0x10)
typedef struct _PLUGPLAY_CONTROL_DEVICE_RELATIONS_DATA {
    UNICODE_STRING DeviceInstance;
    ULONG Relations;
    ULONG BufferSize;
    PWCHAR Buffer;
} PLUGPLAY_CONTROL_DEVICE_RELATIONS_DATA, *PPLUGPLAY_CONTROL_DEVICE_RELATIONS_DATA;

// PlugPlayControlRetrieveDock (0x13)
typedef struct _PLUGPLAY_CONTROL_RETRIEVE_DOCK_DATA {
    ULONG DeviceInstanceLength;
    PWSTR DeviceInstance;
} PLUGPLAY_CONTROL_RETRIEVE_DOCK_DATA, *PPLUGPLAY_CONTROL_RETRIEVE_DOCK_DATA;

// PlugPlayControlQueryHardwareIDs
// PlugPlayControlQueryCompatibleIDs
typedef struct _PLUGPLAY_CONTROL_QUERY_IDS_DATA {
    UNICODE_STRING DeviceInstance;
    ULONG BufferSize;
    PWCHAR Buffer;
} PLUGPLAY_CONTROL_QUERY_IDS_DATA, *PPLUGPLAY_CONTROL_QUERY_IDS_DATA;

//
// Plug and Play Bus Type Definition
//
typedef struct _PLUGPLAY_BUS_TYPE {
    PLUGPLAY_BUS_CLASS BusClass;
    union {
	INTERFACE_TYPE SystemBusType;
	PLUGPLAY_VIRTUAL_BUS_TYPE PlugPlayVirtualBusType;
    };
} PLUGPLAY_BUS_TYPE, *PPLUGPLAY_BUS_TYPE;

//
// Plug and Play Bus Instance Definition
//
typedef struct _PLUGPLAY_BUS_INSTANCE {
    PLUGPLAY_BUS_TYPE BusType;
    ULONG BusNumber;
    WCHAR BusName[MAX_BUS_NAME];
} PLUGPLAY_BUS_INSTANCE, *PPLUGPLAY_BUS_INSTANCE;

typedef struct _PNP_BUS_INFORMATION {
    GUID BusTypeGuid;
    INTERFACE_TYPE LegacyBusType;
    ULONG BusNumber;
} PNP_BUS_INFORMATION, *PPNP_BUS_INFORMATION;

//
// Partial Resource Descriptor and List for Hardware
//
#include <pshpack1.h>
typedef struct _CM_PARTIAL_RESOURCE_DESCRIPTOR {
    UCHAR Type;
    UCHAR ShareDisposition;
    USHORT Flags;
    union {
	struct {
	    PHYSICAL_ADDRESS Start;
	    ULONG Length;
	} Generic;
	struct {
	    PHYSICAL_ADDRESS Start;
	    ULONG Length;
	} Port;
	struct {
	    ULONG Level;
	    ULONG Vector;
	    KAFFINITY Affinity;
	} Interrupt;
	struct {
	    union {
		struct {
		    USHORT Reserved;
		    USHORT MessageCount;
		    ULONG Vector;
		    KAFFINITY Affinity;
		} Raw;
		struct {
		    ULONG Level;
		    ULONG Vector;
		    KAFFINITY Affinity;
		} Translated;
	    };
	} MessageInterrupt;
	struct {
	    PHYSICAL_ADDRESS Start;
	    ULONG Length;
	} Memory;
	struct {
	    ULONG Channel;
	    ULONG Port;
	    ULONG Reserved1;
	} Dma;
	struct {
	    ULONG Data[3];
	} DevicePrivate;
	struct {
	    ULONG Start;
	    ULONG Length;
	    ULONG Reserved;
	} BusNumber;
	struct {
	    ULONG DataSize;
	    ULONG Reserved1;
	    ULONG Reserved2;
	} DeviceSpecificData;
	struct {
	    PHYSICAL_ADDRESS Start;
	    ULONG Length40;
	} Memory40;
	struct {
	    PHYSICAL_ADDRESS Start;
	    ULONG Length48;
	} Memory48;
	struct {
	    PHYSICAL_ADDRESS Start;
	    ULONG Length64;
	} Memory64;
    };
} CM_PARTIAL_RESOURCE_DESCRIPTOR, *PCM_PARTIAL_RESOURCE_DESCRIPTOR;

typedef struct _CM_PARTIAL_RESOURCE_LIST {
    USHORT Version;
    USHORT Revision;
    ULONG Count;
    CM_PARTIAL_RESOURCE_DESCRIPTOR PartialDescriptors[];
} CM_PARTIAL_RESOURCE_LIST, *PCM_PARTIAL_RESOURCE_LIST;

//
// Full Resource Descriptor and List for Hardware
//
typedef struct _CM_FULL_RESOURCE_DESCRIPTOR {
    INTERFACE_TYPE InterfaceType;
    ULONG BusNumber;
    CM_PARTIAL_RESOURCE_LIST PartialResourceList;
} CM_FULL_RESOURCE_DESCRIPTOR, *PCM_FULL_RESOURCE_DESCRIPTOR;

typedef struct _CM_RESOURCE_LIST {
    ULONG Count;
    CM_FULL_RESOURCE_DESCRIPTOR List[];
} CM_RESOURCE_LIST, *PCM_RESOURCE_LIST;

//
// ROM Block Structure
//
typedef struct _CM_ROM_BLOCK {
    ULONG Address;
    ULONG Size;
} CM_ROM_BLOCK, *PCM_ROM_BLOCK;

//
// Disk/INT13 Structures
//
typedef struct _CM_INT13_DRIVE_PARAMETER {
    USHORT DriveSelect;
    ULONG MaxCylinders;
    USHORT SectorsPerTrack;
    USHORT MaxHeads;
    USHORT NumberDrives;
} CM_INT13_DRIVE_PARAMETER, *PCM_INT13_DRIVE_PARAMETER;

typedef struct _CM_DISK_GEOMETRY_DEVICE_DATA {
    ULONG BytesPerSector;
    ULONG NumberOfCylinders;
    ULONG SectorsPerTrack;
    ULONG NumberOfHeads;
} CM_DISK_GEOMETRY_DEVICE_DATA, *PCM_DISK_GEOMETRY_DEVICE_DATA;

#include <poppack.h>

/*
 * Floppy device data
 */
typedef struct _CM_FLOPPY_DEVICE_DATA {
    USHORT Version;
    USHORT Revision;
    CHAR Size[8];
    ULONG MaxDensity;
    ULONG MountDensity;
    UCHAR StepRateHeadUnloadTime;
    UCHAR HeadLoadTime;
    UCHAR MotorOffTime;
    UCHAR SectorLengthCode;
    UCHAR SectorPerTrack;
    UCHAR ReadWriteGapLength;
    UCHAR DataTransferLength;
    UCHAR FormatGapLength;
    UCHAR FormatFillCharacter;
    UCHAR HeadSettleTime;
    UCHAR MotorSettleTime;
    UCHAR MaximumTrackValue;
    UCHAR DataTransferRate;
} CM_FLOPPY_DEVICE_DATA, *PCM_FLOPPY_DEVICE_DATA;

#ifndef _NTOSKRNL_

NTSYSAPI NTSTATUS NtPlugPlayInitialize();

NTAPI NTSYSAPI NTSTATUS NtPlugPlayControl(IN PLUGPLAY_CONTROL_CLASS PlugPlayControlClass,
					  IN OUT PVOID Buffer,
					  IN ULONG BufferSize);

NTAPI NTSYSAPI NTSTATUS NtGetPlugPlayEvent(IN BOOLEAN Poll,
					   OUT PPLUGPLAY_EVENT_BLOCK Buffer,
					   IN ULONG BufferSize);

NTAPI NTSYSAPI NTSTATUS NtCompactKeys(IN ULONG Count,
				      IN PHANDLE KeyArray);

NTAPI NTSYSAPI NTSTATUS NtCompressKey(IN HANDLE Key);

NTAPI NTSYSAPI NTSTATUS NtCreateKey(OUT PHANDLE KeyHandle,
				    IN ACCESS_MASK DesiredAccess,
				    IN POBJECT_ATTRIBUTES ObjectAttributes,
				    IN OPTIONAL ULONG TitleIndex,
				    IN OPTIONAL PUNICODE_STRING Class,
				    IN ULONG CreateOptions,
				    OUT OPTIONAL PULONG Disposition);

NTAPI NTSYSAPI NTSTATUS NtCreateKeyA(OUT HANDLE *KeyHandle,
				     IN ACCESS_MASK DesiredAccess,
				     IN OPTIONAL POBJECT_ATTRIBUTES_ANSI ObjectAttributes,
				     IN ULONG TitleIndex,
				     IN OPTIONAL PCSTR Class,
				     IN ULONG CreateOptions,
				     OUT OPTIONAL ULONG *Disposition);

NTAPI NTSYSAPI NTSTATUS NtDeleteKey(IN HANDLE KeyHandle);

NTAPI NTSYSAPI NTSTATUS NtDeleteValueKey(IN HANDLE KeyHandle,
					 IN PUNICODE_STRING ValueName);

NTAPI NTSYSAPI NTSTATUS NtEnumerateKey(IN HANDLE KeyHandle,
				       IN ULONG Index,
				       IN KEY_INFORMATION_CLASS KeyInformationClass,
				       OUT PVOID KeyInformation,
				       IN ULONG Length,
				       OUT PULONG ResultLength);

NTAPI NTSYSAPI NTSTATUS NtEnumerateValueKey(IN HANDLE KeyHandle,
					    IN ULONG Index,
					    IN KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
					    OUT PVOID KeyValueInformation,
					    IN ULONG Length,
					    OUT PULONG ResultLength);

NTAPI NTSYSAPI NTSTATUS NtFlushKey(IN HANDLE KeyHandle);

NTAPI NTSYSAPI NTSTATUS NtInitializeRegistry(IN USHORT Flag);

NTAPI NTSYSAPI NTSTATUS NtLoadKey(IN POBJECT_ATTRIBUTES KeyObjectAttributes,
				  IN POBJECT_ATTRIBUTES FileObjectAttributes);

NTAPI NTSYSAPI NTSTATUS NtLoadKeyEx(IN POBJECT_ATTRIBUTES TargetKey,
				    IN POBJECT_ATTRIBUTES SourceFile,
				    IN ULONG Flags,
				    IN HANDLE TrustClassKey);

NTAPI NTSYSAPI NTSTATUS NtLockRegistryKey(IN HANDLE KeyHandle);

NTAPI NTSYSAPI NTSTATUS NtNotifyChangeKey(IN HANDLE KeyHandle,
					  IN HANDLE Event,
					  IN OPTIONAL PIO_APC_ROUTINE ApcRoutine,
					  IN OPTIONAL PVOID ApcContext,
					  OUT PIO_STATUS_BLOCK IoStatusBlock,
					  IN ULONG CompletionFilter,
					  IN BOOLEAN Asynchroneous,
					  OUT PVOID ChangeBuffer,
					  IN ULONG Length,
					  IN BOOLEAN WatchSubtree);

NTAPI NTSYSAPI NTSTATUS NtNotifyChangeMultipleKeys(IN HANDLE MasterKeyHandle,
						   IN OPTIONAL ULONG Count,
						   IN OBJECT_ATTRIBUTES SubordinateObjects[],
						   IN OPTIONAL HANDLE Event,
						   IN OPTIONAL PIO_APC_ROUTINE ApcRoutine,
						   IN OPTIONAL PVOID ApcContext,
						   OUT PIO_STATUS_BLOCK IoStatusBlock,
						   IN ULONG CompletionFilter,
						   IN BOOLEAN WatchTree,
						   OUT PVOID Buffer,
						   IN ULONG BufferSize,
						   IN BOOLEAN Asynchronous);

NTAPI NTSYSAPI NTSTATUS NtOpenKey(OUT PHANDLE KeyHandle,
				  IN ACCESS_MASK DesiredAccess,
				  IN POBJECT_ATTRIBUTES ObjectAttributes);

NTAPI NTSYSAPI NTSTATUS NtQueryKey(IN HANDLE KeyHandle,
				   IN KEY_INFORMATION_CLASS KeyInformationClass,
				   OUT PVOID KeyInformation,
				   IN ULONG Length,
				   OUT PULONG ResultLength);

NTAPI NTSYSAPI NTSTATUS NtQueryMultipleValueKey(IN HANDLE KeyHandle,
						IN OUT PKEY_VALUE_ENTRY ValueEntries,
						IN ULONG EntryCount,
						OUT PVOID ValueBuffer,
						IN OUT PULONG BufferLength,
						OUT OPTIONAL PULONG RequiredBufferLength);

NTAPI NTSYSAPI NTSTATUS NtQueryOpenSubKeys(IN POBJECT_ATTRIBUTES TargetKey,
					   OUT PULONG HandleCount);

NTAPI NTSYSAPI NTSTATUS NtQueryOpenSubKeysEx(IN POBJECT_ATTRIBUTES TargetKey,
					     IN ULONG BufferLength,
					     IN PVOID Buffer,
					     IN PULONG RequiredSize);

NTAPI NTSYSAPI NTSTATUS NtQueryValueKey(IN HANDLE KeyHandle,
					IN PUNICODE_STRING ValueName,
					IN KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
					IN PVOID KeyValueInformation,
					IN ULONG Length,
					OUT PULONG ResultLength);

NTAPI NTSYSAPI NTSTATUS NtRenameKey(IN HANDLE KeyHandle,
				    IN PUNICODE_STRING NewName);

NTAPI NTSYSAPI NTSTATUS NtReplaceKey(IN POBJECT_ATTRIBUTES ObjectAttributes,
				     IN HANDLE Key,
				     IN POBJECT_ATTRIBUTES ReplacedObjectAttributes);

NTAPI NTSYSAPI NTSTATUS NtRestoreKey(IN HANDLE KeyHandle,
				     IN HANDLE FileHandle,
				     IN ULONG RestoreFlags);

NTAPI NTSYSAPI NTSTATUS NtSaveKey(IN HANDLE KeyHandle,
				  IN HANDLE FileHandle);

NTAPI NTSYSAPI NTSTATUS NtSaveKeyEx(IN HANDLE KeyHandle,
				    IN HANDLE FileHandle,
				    IN ULONG Flags);

NTAPI NTSYSAPI NTSTATUS NtSaveMergedKeys(IN HANDLE HighPrecedenceKeyHandle,
					 IN HANDLE LowPrecedenceKeyHandle,
					 IN HANDLE FileHandle);

NTAPI NTSYSAPI NTSTATUS NtSetInformationKey(IN HANDLE KeyHandle,
					    IN KEY_SET_INFORMATION_CLASS KeySetInformationClass,
					    IN PVOID KeySetInformation,
					    IN ULONG KeySetInformationLength);

NTAPI NTSYSAPI NTSTATUS NtSetValueKey(IN HANDLE KeyHandle,
				      IN PUNICODE_STRING ValueName,
				      IN OPTIONAL ULONG TitleIndex,
				      IN ULONG Type,
				      IN PVOID Data,
				      IN ULONG DataSize);

NTAPI NTSYSAPI NTSTATUS NtSetValueKeyA(IN HANDLE KeyHandle,
				       IN PCSTR ValueName,
				       IN OPTIONAL ULONG TitleIndex,
				       IN ULONG Type,
				       IN PVOID Data,
				       IN ULONG DataSize);

NTAPI NTSYSAPI NTSTATUS NtUnloadKey(IN POBJECT_ATTRIBUTES KeyObjectAttributes);

#endif	/* !NTOSKRNL */

#if defined(_NTOSKRNL_) || defined(_NTDDK_)

/*
 * Helper functions for the IO resource requirements list
 */

FORCEINLINE PCHAR CmDbgResourceTypeToText(IN UCHAR Type)
{
    /* What kind of resource it this? */
    switch (Type) {
	/* Pick the correct identifier string based on the type */
    case CmResourceTypeDeviceSpecific:
	return "CmResourceTypeDeviceSpecific";
    case CmResourceTypePort:
	return "CmResourceTypePort";
    case CmResourceTypeInterrupt:
	return "CmResourceTypeInterrupt";
    case CmResourceTypeMemory:
	return "CmResourceTypeMemory";
    case CmResourceTypeDma:
	return "CmResourceTypeDma";
    case CmResourceTypeBusNumber:
	return "CmResourceTypeBusNumber";
    case CmResourceTypeConfigData:
	return "CmResourceTypeConfigData";
    case CmResourceTypeDevicePrivate:
	return "CmResourceTypeDevicePrivate";
    case CmResourceTypePcCardConfig:
	return "CmResourceTypePcCardConfig";
    default:
	return "*** INVALID RESOURCE TYPE ***";
    }
}

FORCEINLINE PCSTR IoDbgResourceOptionToStr(ULONG Option)
{
    if (!Option) {
	return "required";
    } else if (Option & IO_RESOURCE_PREFERRED) {
	return "preferred";
    } else if (Option & IO_RESOURCE_ALTERNATIVE) {
	return "alternative";
    } else {
	return "invalid";
    }
}

FORCEINLINE VOID IoDbgPrintResourceDescriptor(IN PIO_RESOURCE_DESCRIPTOR Descriptor)
{
    /* Print out the header */
    DbgPrint("     IoResource Descriptor dump:  Descriptor @ %p\n", Descriptor);
    DbgPrint("        Option           = 0x%x (%s)\n", Descriptor->Option,
	     IoDbgResourceOptionToStr(Descriptor->Option));
    DbgPrint("        Type             = %u (%s)\n", Descriptor->Type,
	     CmDbgResourceTypeToText(Descriptor->Type));
    DbgPrint("        ShareDisposition = %u\n", Descriptor->ShareDisposition);
    DbgPrint("        Flags            = 0x%04X\n", Descriptor->Flags);

    /* Loop private data */
    PULONG Data = Descriptor->DevicePrivate.Data;
    for (ULONG i = 0; i < 6; i += 3) {
	/* Dump it in 32-bit triplets */
	DbgPrint("        Data[%u] = %08x  %08x  %08x\n", i, Data[i], Data[i+1], Data[i+2]);
    }
}

FORCEINLINE VOID IoDbgPrintResouceRequirementsList(IN PIO_RESOURCE_REQUIREMENTS_LIST ReqList)
{
    /* Make sure there's a list */
    if (!ReqList)
	return;

    /* Grab the main list and the alternates as well */
    ULONG AlternativeLists = ReqList->AlternativeLists;
    PIO_RESOURCE_LIST List = ReqList->List;

    /* Print out the initial header*/
    DbgPrint("  IO_RESOURCE_REQUIREMENTS_LIST:\n");
    DbgPrint("     InterfaceType        %d\n", ReqList->InterfaceType);
    DbgPrint("     BusNumber            0x%x\n", ReqList->BusNumber);
    if (ReqList->InterfaceType == PCIBus) {
	DbgPrint("     SlotNumber           %d (0x%x), (d/f = 0x%x/0x%x)\n",
		ReqList->SlotNumber, ReqList->SlotNumber,
		((PCI_SLOT_NUMBER *)&ReqList->SlotNumber)->Bits.DeviceNumber,
		((PCI_SLOT_NUMBER *)&ReqList->SlotNumber)->Bits.FunctionNumber);
    } else {
	DbgPrint("     SlotNumber           %d (0x%x)\n",
		ReqList->SlotNumber, ReqList->SlotNumber);
    }
    DbgPrint("     AlternativeLists     %u\n", AlternativeLists);

    /* Scan alternative lists */
    for (ULONG i = 0; i < AlternativeLists; i++) {
	/* Get the descriptor array, and the count of descriptors */
	PIO_RESOURCE_DESCRIPTOR Descriptor = List->Descriptors;
	ULONG Count = List->Count;

	/* Print out each descriptor */
	DbgPrint("     List[%u].Count = %u\n", i, Count);
	while (Count--)
	    IoDbgPrintResourceDescriptor(Descriptor++);

	/* Should've reached a new list now */
	List = (PIO_RESOURCE_LIST)Descriptor;
    }

    /* Terminate the dump */
    DbgPrint("\n");
}

/*
 * Usage note:
 *
 * As there can be only one variable-sized CM_PARTIAL_RESOURCE_DESCRIPTOR
 * in the list (and it must be the last one), a correct looping through resources
 * can look like this:
 *
 *   PCM_FULL_RESOURCE_DESCRIPTOR FullDesc = &ResourceList->List[0];
 *   for (ULONG i = 0; i < ResourceList->Count;
 *        i++, FullDesc = CmiGetNextResourceDescriptor(FullDesc)) {
 *       for (ULONG j = 0; j < FullDesc->PartialResourceList.Count; j++) {
 *           PartialDesc = &FullDesc->PartialResourceList.PartialDescriptors[j];
 *            // work with PartialDesc
 *       }
 *   }
 */
FORCEINLINE PCM_PARTIAL_RESOURCE_DESCRIPTOR
CmGetNextPartialDescriptor(IN CONST CM_PARTIAL_RESOURCE_DESCRIPTOR *Partial)
{
    /* Assume the descriptors are the fixed size ones */
    const CM_PARTIAL_RESOURCE_DESCRIPTOR *Next = Partial + 1;

    /* But check if this is actually a variable-sized descriptor */
    if (Partial->Type == CmResourceTypeDeviceSpecific) {
	/* Add the size of the variable section as well */
	Next = (PCM_PARTIAL_RESOURCE_DESCRIPTOR)((ULONG_PTR)Next +
						 Partial->DeviceSpecificData.DataSize);
	ASSERT(Next >= Partial + 1);
    }

    /* Now the correct pointer has been computed, return it */
    return (PCM_PARTIAL_RESOURCE_DESCRIPTOR)Next;
}

FORCEINLINE PCM_FULL_RESOURCE_DESCRIPTOR
CmGetNextResourceDescriptor(IN CONST CM_FULL_RESOURCE_DESCRIPTOR *Res)
{
    /* Calculate the location of the last partial descriptor, which can have a
       variable size! */
    const CM_PARTIAL_RESOURCE_DESCRIPTOR *Last =
	&Res->PartialResourceList.PartialDescriptors[Res->PartialResourceList.Count - 1];

    /* Next full resource descriptor follows the last partial descriptor */
    return (PCM_FULL_RESOURCE_DESCRIPTOR)CmGetNextPartialDescriptor(Last);
}

FORCEINLINE ULONG CmGetResourceListSize(IN PCM_RESOURCE_LIST Res)
{
    if (!Res) {
	return 0;
    }
    ULONG ResSize = sizeof(CM_RESOURCE_LIST) + Res->Count * sizeof(CM_FULL_RESOURCE_DESCRIPTOR);
    PCM_FULL_RESOURCE_DESCRIPTOR Desc = Res->List;
    for (ULONG i = 0; i < Res->Count; i++) {
	ResSize += Desc->PartialResourceList.Count * sizeof(CM_PARTIAL_RESOURCE_DESCRIPTOR);
	Desc = CmGetNextResourceDescriptor(Desc);
    }
    return ResSize;
}

FORCEINLINE VOID CmDbgPrintResourceDescriptor(IN PCM_PARTIAL_RESOURCE_DESCRIPTOR Res)
{
    /* Dump all the data in the partial */
    DbgPrint("     Partial Resource Descriptor @ %p\n", Res);
    DbgPrint("        Type             = %u (%s)\n", Res->Type,
	     CmDbgResourceTypeToText(Res->Type));
    DbgPrint("        ShareDisposition = %u\n", Res->ShareDisposition);
    DbgPrint("        Flags            = 0x%04X\n", Res->Flags);
    DbgPrint("        Data[%d] = %08x  %08x  %08x\n", 0,
	     Res->Generic.Start.LowPart,
	     Res->Generic.Start.HighPart, Res->Generic.Length);
}

FORCEINLINE VOID CmDbgPrintResourceList(IN PCM_RESOURCE_LIST PartialList)
{
    /* Make sure there's something to dump */
    if (!PartialList)
	return;

    /* Get the full list count */
    ULONG ListCount = PartialList->Count;
    PCM_FULL_RESOURCE_DESCRIPTOR FullDescriptor = PartialList->List;
    DbgPrint("  CM_RESOURCE_LIST (List Count = %u)\n",
	     PartialList->Count);

    /* Loop full list */
    for (ULONG i = 0; i < ListCount; i++) {
	/* Loop full descriptor */
	DbgPrint("     InterfaceType        %d\n", FullDescriptor->InterfaceType);
	DbgPrint("     BusNumber            0x%x\n", FullDescriptor->BusNumber);

	/* Get partial count and loop partials */
	PCM_PARTIAL_RESOURCE_DESCRIPTOR PartialDescriptor =
	    FullDescriptor->PartialResourceList.PartialDescriptors;
	for (ULONG Count = FullDescriptor->PartialResourceList.Count; Count; Count--) {
	    /* Print each partial resource descriptor */
	    CmDbgPrintResourceDescriptor(PartialDescriptor);
	    PartialDescriptor = CmGetNextPartialDescriptor(PartialDescriptor);
	}

	/* Go to the next full descriptor */
	FullDescriptor = (PCM_FULL_RESOURCE_DESCRIPTOR)PartialDescriptor;
    }

    /* Done printing data */
    DbgPrint("\n");
}

#endif	/* defined(_NTOSKRNL_) || defined(_NTDDK_) */
