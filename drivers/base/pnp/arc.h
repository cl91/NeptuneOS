#include <wdm.h>

typedef enum _IDENTIFIER_FLAG {
    Failed = 0x01,
    ReadOnly = 0x02,
    Removable = 0x04,
    ConsoleIn = 0x08,
    ConsoleOut = 0x10,
    Input = 0x20,
    Output = 0x40
} IDENTIFIER_FLAG;

typedef enum _CONFIGURATION_CLASS {
    SystemClass,
    ProcessorClass,
    CacheClass,
    AdapterClass,
    ControllerClass,
    PeripheralClass,
    MemoryClass,
    MaximumClass
} CONFIGURATION_CLASS;

typedef struct _CONFIGURATION_COMPONENT {
    CONFIGURATION_CLASS Class;
    CONFIGURATION_TYPE Type;
    IDENTIFIER_FLAG Flags;
    USHORT Version;
    USHORT Revision;
    ULONG Key;
    ULONG AffinityMask;
    ULONG ConfigurationDataLength;
    ULONG IdentifierLength;
    PCHAR Identifier;
} CONFIGURATION_COMPONENT, *PCONFIGURATION_COMPONENT;

typedef struct _CONFIGURATION_COMPONENT_DATA {
    struct _CONFIGURATION_COMPONENT_DATA *Parent;
    struct _CONFIGURATION_COMPONENT_DATA *Child;
    struct _CONFIGURATION_COMPONENT_DATA *Sibling;
    CONFIGURATION_COMPONENT ComponentEntry;
    PVOID ConfigurationData;
} CONFIGURATION_COMPONENT_DATA, *PCONFIGURATION_COMPONENT_DATA;

/* arc.c */
NTSTATUS ArcCreateSystemKey(OUT PCONFIGURATION_COMPONENT_DATA *SystemNode);
NTSTATUS ArcCreateComponentKey(IN PCONFIGURATION_COMPONENT_DATA SystemNode,
			       IN CONFIGURATION_CLASS Class,
			       IN CONFIGURATION_TYPE Type,
			       IN IDENTIFIER_FLAG Flags,
			       IN ULONG Key,
			       IN ULONG Affinity,
			       IN PCHAR IdentifierString,
			       IN PCM_PARTIAL_RESOURCE_LIST ResourceList,
			       IN ULONG Size,
			       OUT PCONFIGURATION_COMPONENT_DATA *ComponentKey);
VOID ArcDestroySystemKey(IN PCONFIGURATION_COMPONENT_DATA SystemNode);
NTSTATUS ArcSetupHardwareDescriptionDatabase(IN PCONFIGURATION_COMPONENT_DATA ConfigurationRoot);
