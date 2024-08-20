#pragma once

#define WMIREG_ACTION_REGISTER      1
#define WMIREG_ACTION_DEREGISTER    2
#define WMIREG_ACTION_REREGISTER    3
#define WMIREG_ACTION_UPDATE_GUIDS  4
#define WMIREG_ACTION_BLOCK_IRPS    5

#define WMIREGISTER                 0
#define WMIUPDATE                   1

typedef enum _WMIENABLEDISABLECONTROL {
    WmiEventControl,
    WmiDataBlockControl
} WMIENABLEDISABLECONTROL, *PWMIENABLEDISABLECONTROL;

typedef enum _SYSCTL_IRP_DISPOSITION {
    IrpProcessed,
    IrpNotCompleted,
    IrpNotWmi,
    IrpForward
} SYSCTL_IRP_DISPOSITION, *PSYSCTL_IRP_DISPOSITION;

typedef struct _WMIGUIDREGINFO {
    LPCGUID Guid;
    ULONG InstanceCount;
    ULONG Flags;
} WMIGUIDREGINFO, *PWMIGUIDREGINFO;

typedef NTSTATUS (NTAPI *PWMI_QUERY_REGINFO)(IN OUT PDEVICE_OBJECT DeviceObject,
					     IN OUT PULONG RegFlags,
					     IN OUT PUNICODE_STRING InstanceName,
					     OUT PUNICODE_STRING *RegistryPath OPTIONAL,
					     IN OUT PUNICODE_STRING MofResourceName,
					     OUT PDEVICE_OBJECT *Pdo OPTIONAL);

typedef NTSTATUS (NTAPI *PWMI_FUNCTION_CONTROL)(IN OUT PDEVICE_OBJECT DeviceObject,
						IN OUT PIRP Irp, IN ULONG GuidIndex,
						IN WMIENABLEDISABLECONTROL Function,
						IN BOOLEAN Enable);

typedef NTSTATUS (NTAPI *PWMI_QUERY_DATABLOCK)(IN OUT PDEVICE_OBJECT DeviceObject,
					       IN OUT PIRP Irp, IN ULONG GuidIndex,
					       IN ULONG InstanceIndex,
					       IN ULONG InstanceCount,
					       OUT PULONG InstanceLengthArray OPTIONAL,
					       IN ULONG BufferAvail,
					       OUT PUCHAR Buffer OPTIONAL);

typedef NTSTATUS (NTAPI *PWMI_EXECUTE_METHOD)(IN OUT PDEVICE_OBJECT DeviceObject,
					      IN OUT PIRP Irp, IN ULONG GuidIndex,
					      IN ULONG InstanceIndex, IN ULONG MethodId,
					      IN ULONG InBufferSize,
					      IN ULONG OutBufferSize,
					      IN OUT PUCHAR Buffer);

typedef NTSTATUS (NTAPI *PWMI_SET_DATABLOCK)(IN OUT PDEVICE_OBJECT DeviceObject,
					     IN OUT PIRP Irp, IN ULONG GuidIndex,
					     IN ULONG InstanceIndex, IN ULONG BufferSize,
					     IN PUCHAR Buffer);

typedef NTSTATUS (NTAPI *PWMI_SET_DATAITEM)(IN OUT PDEVICE_OBJECT DeviceObject,
					    IN OUT PIRP Irp, IN ULONG GuidIndex,
					    IN ULONG InstanceIndex, IN ULONG DataItemId,
					    IN ULONG BufferSize, IN PUCHAR Buffer);

typedef struct _WMILIB_CONTEXT {
    ULONG GuidCount;
    PWMIGUIDREGINFO GuidList;
    PWMI_QUERY_REGINFO QueryWmiRegInfo;
    PWMI_QUERY_DATABLOCK QueryWmiDataBlock;
    PWMI_SET_DATABLOCK SetWmiDataBlock;
    PWMI_SET_DATAITEM SetWmiDataItem;
    PWMI_EXECUTE_METHOD ExecuteWmiMethod;
    PWMI_FUNCTION_CONTROL WmiFunctionControl;
} WMILIB_CONTEXT, *PWMILIB_CONTEXT;

NTAPI NTSTATUS WmiCompleteRequest(IN PDEVICE_OBJECT DeviceObject, IN OUT PIRP Irp,
				  IN NTSTATUS Status, IN ULONG BufferUsed,
				  IN CCHAR PriorityBoost);

NTAPI NTSTATUS WmiSystemControl(IN PWMILIB_CONTEXT WmiLibInfo,
				IN PDEVICE_OBJECT DeviceObject, IN OUT PIRP Irp,
				OUT PSYSCTL_IRP_DISPOSITION IrpDisposition);

NTAPI NTSTATUS WmiFireEvent(IN PDEVICE_OBJECT DeviceObject, IN LPCGUID Guid,
			    IN ULONG InstanceIndex, IN ULONG EventDataSize,
			    IN PVOID EventData);
