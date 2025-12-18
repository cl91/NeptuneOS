#ifndef _MNTMGR_H_
#define _MNTMGR_H_

#include <initguid.h>
#include <ntifs.h>
#include <mountdev.h>
#include <ntddvol.h>
#include <ntdddisk.h>
#include <wdmguid.h>
#include <ntdddisk.h>

typedef struct _DEVICE_EXTENSION {
    PDEVICE_OBJECT DeviceObject;
    PDRIVER_OBJECT DriverObject;
    LIST_ENTRY DeviceListHead;
    LIST_ENTRY OfflineDeviceListHead;
    PVOID NotificationEntry;
    KEVENT DeviceLock;
    KEVENT RemoteDatabaseLock;
    BOOLEAN AutomaticDriveLetter;
    LIST_ENTRY IrpListHead;
    ULONG EpicNumber;
    LIST_ENTRY SavedLinksListHead;
    BOOLEAN ProcessedSuggestions;
    BOOLEAN NoAutoMount;
    LIST_ENTRY WorkerQueueListHead;
    LIST_ENTRY UniqueIdWorkerItemListHead;
    PMOUNTDEV_UNIQUE_ID DriveLetterData;
    UNICODE_STRING RegistryPath;
    LONG WorkerThreadStatus;
    LIST_ENTRY OnlineNotificationListHead;
    ULONG OnlineNotificationWorkerActive;
    ULONG OnlineNotificationCount;
    KEVENT OnlineNotificationEvent;
} DEVICE_EXTENSION, *PDEVICE_EXTENSION;

typedef struct _DEVICE_INFORMATION {
    LIST_ENTRY DeviceListEntry;
    LIST_ENTRY SymbolicLinksListHead;
    LIST_ENTRY ReplicatedUniqueIdsListHead;
    LIST_ENTRY AssociatedDevicesHead;
    PMOUNTDEV_UNIQUE_ID UniqueId;
    PVOID TargetDeviceNotificationEntry;
    PDEVICE_EXTENSION DeviceExtension;
    UNICODE_STRING SymbolicName;
    UNICODE_STRING DeviceName;
    ULONG Migrated;
    UCHAR SuggestedDriveLetter;
    BOOLEAN KeepLinks;
    BOOLEAN ManuallyRegistered;
    BOOLEAN Removable;
    BOOLEAN LetterAssigned;
    BOOLEAN NeedsReconcile;
    BOOLEAN NoDatabase;
    BOOLEAN SkipNotifications;
    BOOLEAN MountState;
} DEVICE_INFORMATION, *PDEVICE_INFORMATION;

typedef struct _SYMLINK_INFORMATION {
    LIST_ENTRY SymbolicLinksListEntry;
    UNICODE_STRING Name;
    BOOLEAN Online;
} SYMLINK_INFORMATION, *PSYMLINK_INFORMATION;

typedef struct _SAVED_LINK_INFORMATION {
    LIST_ENTRY SavedLinksListEntry;
    LIST_ENTRY SymbolicLinksListHead;
    PMOUNTDEV_UNIQUE_ID UniqueId;
} SAVED_LINK_INFORMATION, *PSAVED_LINK_INFORMATION;

typedef struct _UNIQUE_ID_REPLICATE {
    LIST_ENTRY ReplicatedUniqueIdsListEntry;
    PMOUNTDEV_UNIQUE_ID UniqueId;
} UNIQUE_ID_REPLICATE, *PUNIQUE_ID_REPLICATE;

typedef struct _DATABASE_ENTRY {
    ULONG EntrySize;
    ULONG EntryReferences;
    USHORT SymbolicNameOffset;
    USHORT SymbolicNameLength;
    USHORT UniqueIdOffset;
    USHORT UniqueIdLength;
} DATABASE_ENTRY, *PDATABASE_ENTRY;

typedef struct _ASSOCIATED_DEVICE_ENTRY {
    LIST_ENTRY AssociatedDevicesEntry;
    PDEVICE_INFORMATION DeviceInformation;
    UNICODE_STRING String;
} ASSOCIATED_DEVICE_ENTRY, *PASSOCIATED_DEVICE_ENTRY;

typedef struct _DEVICE_INFORMATION_ENTRY {
    LIST_ENTRY DeviceInformationEntry;
    PDEVICE_INFORMATION DeviceInformation;
} DEVICE_INFORMATION_ENTRY, *PDEVICE_INFORMATION_ENTRY;

typedef struct _ONLINE_NOTIFICATION_WORK_ITEM {
    IO_WORKITEM WorkItem;
    LIST_ENTRY Link;
    PDEVICE_EXTENSION DeviceExtension;
    UNICODE_STRING SymbolicName;
} ONLINE_NOTIFICATION_WORK_ITEM, *PONLINE_NOTIFICATION_WORK_ITEM;

typedef struct _RECONCILE_WORK_ITEM_CONTEXT {
    PDEVICE_EXTENSION DeviceExtension;
    PDEVICE_INFORMATION DeviceInformation;
} RECONCILE_WORK_ITEM_CONTEXT, *PRECONCILE_WORK_ITEM_CONTEXT;

typedef struct _RECONCILE_WORK_ITEM {
    LIST_ENTRY WorkerQueueListEntry;
    PIO_WORKITEM WorkItem;
    VOID (NTAPI *WorkerRoutine)(PVOID);
    PVOID Context;
    RECONCILE_WORK_ITEM_CONTEXT ReconcileWorkItemContext;
} RECONCILE_WORK_ITEM, *PRECONCILE_WORK_ITEM;

typedef struct _MIGRATE_WORK_ITEM {
    PIO_WORKITEM WorkItem;
    PDEVICE_INFORMATION DeviceInformation;
    PKEVENT Event;
    NTSTATUS Status;
    HANDLE Database;
} MIGRATE_WORK_ITEM, *PMIGRATE_WORK_ITEM;

typedef struct _UNIQUE_ID_WORK_ITEM {
    LIST_ENTRY UniqueIdWorkerItemListEntry;
    PIO_WORKITEM WorkItem;
    PDEVICE_EXTENSION DeviceExtension;
    PIRP Irp;
    PVOID IrpBuffer;
    PKEVENT Event;
    UNICODE_STRING DeviceName;
    ULONG IrpBufferLength;
    ULONG StackSize;
} UNIQUE_ID_WORK_ITEM, *PUNIQUE_ID_WORK_ITEM;

/* Memory allocation helpers */
#define AllocatePool(Size) ExAllocatePoolWithTag(PagedPool, Size, 'AtnM')
#define FreePool(P) ExFreePoolWithTag(P, 'AtnM')

/* Misc macros */
#define MAX(a, b) ((a > b) ? a : b)

#define LETTER_POSITION 0xC
#define COLON_POSITION 0xD
#define DRIVE_LETTER_LENGTH 0x1C

/* mountmgr.c */

extern UNICODE_STRING DosDevicesMount;
extern UNICODE_STRING ReparseIndex;
extern UNICODE_STRING DeviceFloppy;
extern UNICODE_STRING DeviceMount;
extern UNICODE_STRING DeviceCdRom;
extern UNICODE_STRING SafeVolumes;
extern UNICODE_STRING DosDevices;
extern UNICODE_STRING DosGlobal;
extern UNICODE_STRING Global;
extern UNICODE_STRING Volume;
extern KEVENT UnloadEvent;
extern LONG Unloading;

DRIVER_INITIALIZE DriverEntry;

NTSTATUS MountMgrSendSyncDeviceIoCtl(IN ULONG IoControlCode,
				     IN PDEVICE_OBJECT DeviceObject,
				     IN OPTIONAL PVOID InputBuffer,
				     IN ULONG InputBufferLength,
				     OUT OPTIONAL PVOID OutputBuffer,
				     IN ULONG OutputBufferLength,
				     IN OPTIONAL PFILE_OBJECT FileObject);

NTAPI VOID MountMgrCancel(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);

NTSTATUS MountMgrMountedDeviceArrival(IN PDEVICE_EXTENSION Extension,
				      IN PUNICODE_STRING SymbolicName,
				      IN BOOLEAN FromVolume);

VOID MountMgrMountedDeviceRemoval(IN PDEVICE_EXTENSION Extension,
				  IN PUNICODE_STRING DeviceName);

NTSTATUS FindDeviceInfo(IN PDEVICE_EXTENSION DeviceExtension,
			IN PUNICODE_STRING SymbolicName,
			IN BOOLEAN DeviceNameGiven,
			OUT PDEVICE_INFORMATION *DeviceInformation);

VOID MountMgrFreeDeadDeviceInfo(IN PDEVICE_INFORMATION DeviceInformation);

NTSTATUS QueryDeviceInformation(IN PUNICODE_STRING SymbolicName,
				OUT OPTIONAL PUNICODE_STRING DeviceName,
				OUT OPTIONAL PMOUNTDEV_UNIQUE_ID *UniqueId,
				OUT OPTIONAL PBOOLEAN Removable,
				OUT OPTIONAL PBOOLEAN GptDriveLetter,
				OUT OPTIONAL PBOOLEAN HasGuid,
				IN OUT OPTIONAL LPGUID StableGuid,
				OUT OPTIONAL PBOOLEAN IsFT);

BOOLEAN
HasDriveLetter(IN PDEVICE_INFORMATION DeviceInformation);

/* database.c */

extern PWSTR DatabasePath;
extern PWSTR OfflinePath;

VOID ReconcileThisDatabaseWithMaster(IN PDEVICE_EXTENSION DeviceExtension,
				     IN PDEVICE_INFORMATION DeviceInformation);

NTSTATUS
WaitForRemoteDatabaseSemaphore(IN PDEVICE_EXTENSION DeviceExtension);

VOID ReleaseRemoteDatabaseSemaphore(IN PDEVICE_EXTENSION DeviceExtension);

VOID ChangeRemoteDatabaseUniqueId(IN PDEVICE_INFORMATION DeviceInformation,
				  IN PMOUNTDEV_UNIQUE_ID OldUniqueId,
				  IN PMOUNTDEV_UNIQUE_ID NewUniqueId);

VOID ReconcileAllDatabasesWithMaster(IN PDEVICE_EXTENSION DeviceExtension);

VOID DeleteFromLocalDatabase(IN PUNICODE_STRING SymbolicLink,
			     IN PMOUNTDEV_UNIQUE_ID UniqueId);

VOID DeleteRegistryDriveLetter(IN PMOUNTDEV_UNIQUE_ID UniqueId);

VOID DeleteNoDriveLetterEntry(IN PMOUNTDEV_UNIQUE_ID UniqueId);

NTSTATUS QueryVolumeName(IN HANDLE RootDirectory,
			 IN PFILE_REPARSE_POINT_INFORMATION ReparsePointInformation,
			 IN OPTIONAL PUNICODE_STRING FileName,
			 OUT PUNICODE_STRING SymbolicName,
			 OUT PUNICODE_STRING VolumeName);

HANDLE OpenRemoteDatabase(IN PDEVICE_INFORMATION DeviceInformation,
			  IN BOOLEAN MigrateDatabase);

PDATABASE_ENTRY GetRemoteDatabaseEntry(IN HANDLE Database, IN LONG StartingOffset);

NTSTATUS WriteRemoteDatabaseEntry(IN HANDLE Database,
				  IN LONG Offset,
				  IN PDATABASE_ENTRY Entry);

NTSTATUS CloseRemoteDatabase(IN HANDLE Database);

NTSTATUS AddRemoteDatabaseEntry(IN HANDLE Database, IN PDATABASE_ENTRY Entry);

NTSTATUS DeleteRemoteDatabaseEntry(IN HANDLE Database, IN LONG StartingOffset);

NTAPI VOID ReconcileThisDatabaseWithMasterWorker(IN PVOID Parameter);

/* device.c */

DRIVER_DISPATCH MountMgrDeviceControl;

/* notify.c */

VOID IssueUniqueIdChangeNotifyWorker(IN PUNIQUE_ID_WORK_ITEM WorkItem,
				     IN PMOUNTDEV_UNIQUE_ID UniqueId);

VOID WaitForOnlinesToComplete(IN PDEVICE_EXTENSION DeviceExtension);

VOID RegisterForTargetDeviceNotification(IN PDEVICE_EXTENSION DeviceExtension,
					 IN PDEVICE_INFORMATION DeviceInformation);

VOID SendOnlineNotification(IN PUNICODE_STRING SymbolicName);

VOID IssueUniqueIdChangeNotify(IN PDEVICE_EXTENSION DeviceExtension,
			       IN PUNICODE_STRING DeviceName,
			       IN PMOUNTDEV_UNIQUE_ID UniqueId);

VOID PostOnlineNotification(IN PDEVICE_EXTENSION DeviceExtension,
			    IN PUNICODE_STRING SymbolicName);

VOID MountMgrNotify(IN PDEVICE_EXTENSION DeviceExtension);

VOID MountMgrNotifyNameChange(IN PDEVICE_EXTENSION DeviceExtension,
			      IN PUNICODE_STRING DeviceName,
			      IN BOOLEAN ValidateVolume);

/* uniqueid.c */

VOID MountMgrUniqueIdChangeRoutine(IN PDEVICE_EXTENSION DeviceExtension,
				   IN PMOUNTDEV_UNIQUE_ID OldUniqueId,
				   IN PMOUNTDEV_UNIQUE_ID NewUniqueId);

VOID CreateNoDriveLetterEntry(IN PMOUNTDEV_UNIQUE_ID UniqueId);

BOOLEAN HasNoDriveLetterEntry(IN PMOUNTDEV_UNIQUE_ID UniqueId);

VOID UpdateReplicatedUniqueIds(IN PDEVICE_INFORMATION DeviceInformation,
			       IN PDATABASE_ENTRY DatabaseEntry);

BOOLEAN IsUniqueIdPresent(IN PDEVICE_EXTENSION DeviceExtension,
			  IN PDATABASE_ENTRY DatabaseEntry);

/* point.c */

NTSTATUS MountMgrCreatePointWorker(IN PDEVICE_EXTENSION DeviceExtension,
				   IN PUNICODE_STRING SymbolicLinkName,
				   IN PUNICODE_STRING DeviceName);

NTSTATUS
QueryPointsFromSymbolicLinkName(IN PDEVICE_EXTENSION DeviceExtension,
				IN PUNICODE_STRING SymbolicName, IN PIRP Irp);

NTSTATUS QueryPointsFromMemory(IN PDEVICE_EXTENSION DeviceExtension,
			       IN PIRP Irp,
			       IN OPTIONAL PMOUNTDEV_UNIQUE_ID UniqueId,
			       IN OPTIONAL PUNICODE_STRING SymbolicName);

/* symlink.c */

NTSTATUS GlobalCreateSymbolicLink(IN PUNICODE_STRING DosName,
				  IN PUNICODE_STRING DeviceName);

NTSTATUS GlobalDeleteSymbolicLink(IN PUNICODE_STRING DosName);

NTSTATUS QuerySuggestedLinkName(IN PUNICODE_STRING SymbolicName,
				OUT PUNICODE_STRING SuggestedLinkName,
				OUT PBOOLEAN UseOnlyIfThereAreNoOtherLinks);

NTSTATUS QuerySymbolicLinkNamesFromStorage(IN PDEVICE_EXTENSION DeviceExtension,
					   IN PDEVICE_INFORMATION DeviceInformation,
					   IN PUNICODE_STRING SuggestedLinkName,
					   IN BOOLEAN UseOnlyIfThereAreNoOtherLinks,
					   OUT PUNICODE_STRING *SymLinks,
					   OUT PULONG SymLinkCount,
					   IN BOOLEAN HasGuid,
					   IN LPGUID Guid);

PSAVED_LINK_INFORMATION RemoveSavedLinks(IN PDEVICE_EXTENSION DeviceExtension,
					 IN PMOUNTDEV_UNIQUE_ID UniqueId);

BOOLEAN RedirectSavedLink(IN PSAVED_LINK_INFORMATION SavedLinkInformation,
			  IN PUNICODE_STRING DosName,
			  IN PUNICODE_STRING NewLink);

VOID SendLinkCreated(IN PUNICODE_STRING SymbolicName);

NTSTATUS CreateNewVolumeName(OUT PUNICODE_STRING VolumeName,
			     IN OPTIONAL PGUID VolumeGuid);

BOOLEAN IsDriveLetter(PUNICODE_STRING SymbolicName);

VOID DeleteSymbolicLinkNameFromMemory(IN PDEVICE_EXTENSION DeviceExtension,
				      IN PUNICODE_STRING SymbolicLink,
				      IN BOOLEAN MarkOffline);

NTSTATUS MountMgrQuerySymbolicLink(IN PUNICODE_STRING SymbolicName,
				   IN OUT PUNICODE_STRING LinkTarget);

#endif /* _MNTMGR_H_ */
