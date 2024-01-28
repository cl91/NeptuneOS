/*
 * PROJECT:        ReactOS Floppy Disk Controller Driver
 * LICENSE:        GNU GPLv2 only as published by the Free Software Foundation
 * FILE:           drivers/storage/fdc/fdc/fdc.h
 * PURPOSE:        Common header file
 * PROGRAMMERS:    Eric Kohl
 * NOTES:
 *    This is the PnP driver for PC floppy disk controllers. Somewhat
 * confusingly, it is both a bus driver and a function driver. The reason
 * for this is that a floppy disk controller (FDC) can in fact support
 * multiple floppy drives: one FDC can control two floppy cables, and
 * each cable supports up to two drives [0]. Therefore this driver, when
 * responding to the QueryBusRelations call from the PnP manager, acts as
 * a bus driver that enumerates all connected drives. This part of the
 * driver is implemented in fdo.c (a confusing name at first sight, but
 * it will become apparent below why this is correct). For each connected
 * drive, this driver acts as their function driver, implemented in pdo.c.
 *
 * There are several device objects here, with terms such as PDOs
 * (physical device objects) and FDOs (function device objects).
 * These can be rather confusing, so here is the schematic diagram of
 * all the PDOs and FDOs involved.
 *
 *     |-----------|
 *     | Drive PDO | (\Device\Floppy0, etc)
 *     |-----------|
 *           |                    |----------------|
 *           |<-------------------| Controller FDO | (unnamed)
 *  Creates Drive PDO as a result |----------------|
 *  of QueryBusRelations                  ^
 *                                        | Creates Controller FDO
 *                                        | in AddDevice routine
 *                                        |
 *                                |----------------|
 *                                | Controller PDO | (unnamed)
 *                                |----------------|
 *       Created by parent bus driver as  |              |----------------|
 *       a result of QueryBusRelations    |<-------------| Parent bus FDO |
 *                                                       |----------------|
 *
 *
 * When the system starts up (or whenever the user asks the PnP manager
 * to enumerate the PnP devices present in the system) the parent bus
 * (typically acpi.sys or pnp.sys) enumerates the floppy disk controllers
 * connected to the system (for most systems, there is only one FDC).
 * The parent bus creates the Controller PDO as a result of the PNP IRP
 * with minor code QueryBusRelations. The PnP manager then loads us into
 * memory, and passes the Controller PDO into the AddDevice routine of us.
 * The AddDevice routine creates the Controller FDO, which acts as a bus
 * device that enumerates the floppy drives connected to the FDC. The PnP
 * manager will then send QueryBusRelations to the Controller FDO, which
 * will create a Drive PDO for each floppy drive connected to the FDC.
 * The Controller FDO has the device extension struct FDO_DEVICE_EXTENSION,
 * which records the Controller PDO as one of its members. The Drive PDO
 * has the device extension PDO_DEVICE_EXTENSION, which records the
 * Controller PDO as one of its members. Please refer to the comments down
 * below for further details.
 *
 * To make things even more confusing, for the function driver part, this
 * driver merges the port driver and class driver functionalities that
 * one expects in a corresponding Windows system. On a Windows NT (more
 * specifically NT 5.x) system there is the FDC port driver fdc.sys, which
 * exposes a device object \Device\FloppyPDOn for each connected drive #n.
 * On top of the port driver, NT 5.x has a class driver flpydisk.sys,
 * which implements the common read/write/ioctl interface for floppy disks
 * exposed via a device object \Device\Floppyn for each connected drive #n.
 * The reason for this design is presumably that one can swap the port
 * driver for another port driver for a different floppy disk controller
 * (for instance, the Model 30 FDC found in IBM Thinkpad 750). Since on
 * Neptune OS we don't support anything earlier than a Pentium II PC, we
 * only have one kind of FDC port driver. Therefore to simplify driver
 * design (and to reduce the number of context switches because we are a
 * micro-kernel OS), we have decided to merge the port driver with the
 * class driver, and expose \Device\Floppyn for each enumerated drive.

 * The code is adapted from storage\floppy\fdc and storage\floppy\floppy
 * in the ReactOS source tree.
 *
 * [0] https://wiki.osdev.org/Floppy_Disk_Controller
 */

#pragma once

#include <ntddk.h>
#include <hal.h>
#include <ntdddisk.h>
#include <mountdev.h>
#include <debug.h>

#define MAX_ARC_PATH_LEN 255
#define MAX_DRIVES_PER_CONTROLLER 4
#define MAX_CONTROLLERS 4

/*
 * MEDIA TYPES
 *
 * This table was found at http://www.nondot.org/sabre/os/files/Disk/FloppyMediaIDs.txt.
 * Thanks to raster@indirect.com for this information.
 *
 * Format   Size   Cyls   Heads  Sec/Trk   FATs   Sec/FAT   Sec/Root   Media
 * 160K     5 1/4   40      1       8       2        ?         ?        FE
 * 180K     5 1/4   40      1       9       2        ?         4        FC
 * 320K     5 1/4   40      2       8       2        ?         ?        FF
 * 360K     5 1/4   40      2       9       2        4         7        FD
 * 1.2M     5 1/4   80      2      15       2       14        14        F9
 * 720K     3 1/2   80      2       9       2        6         7        F9
 * 1.44M    3 1/2   80      2      18       2       18        14        F0
 */

#define GEOMETRY_144_MEDIATYPE		F3_1Pt44_512
#define GEOMETRY_144_CYLINDERS		80
#define GEOMETRY_144_TRACKSPERCYLINDER	2
#define GEOMETRY_144_SECTORSPERTRACK	18
#define GEOMETRY_144_BYTESPERSECTOR	512

#define MAX_DEVICE_NAME		256

/*
 * Drive info
 */
struct _CONTROLLER_INFO;
typedef struct _DRIVE_INFO {
    struct _CONTROLLER_INFO *ControllerInfo;
    UCHAR                    UnitNumber;		/* 0,1,2,3 */
    ULONG                    PeripheralNumber;
    PDEVICE_OBJECT           DeviceObject;
    CM_FLOPPY_DEVICE_DATA    FloppyDeviceData;
//    LARGE_INTEGER            MotorStartTime;
    DISK_GEOMETRY            DiskGeometry;
    UCHAR                    BytesPerSectorCode;
    WCHAR                    DeviceNameBuffer[MAX_DEVICE_NAME];
//    WCHAR                    SymLinkBuffer[MAX_DEVICE_NAME];
//    WCHAR                    ArcPathBuffer[MAX_ARC_PATH_LEN];
    ULONG                    DiskChangeCount;
//    BOOLEAN                  Initialized;
} DRIVE_INFO, *PDRIVE_INFO;

/*
 * Controller info
 */
typedef struct _CONTROLLER_INFO {
    BOOLEAN          Populated;
    BOOLEAN          Initialized;
    ULONG            ControllerNumber;
    INTERFACE_TYPE   InterfaceType;
    ULONG            BusNumber;
    ULONG            Level;
    ULONG            Vector;
    KINTERRUPT_MODE  InterruptMode;
    KAFFINITY        Affinity;
    BOOLEAN          ShareInterrupt;
    PUCHAR           BaseAddress;
    ULONG            Dma;
    ULONG            MapRegisters;
    PVOID            MapRegisterBase;
//    BOOLEAN          Master;
    KEVENT           SynchEvent;
    PKINTERRUPT      InterruptObject;
    PDMA_ADAPTER     AdapterObject;
    UCHAR            NumberOfDrives;
    BOOLEAN          ImpliedSeeks;
    DRIVE_INFO       DriveInfo[MAX_DRIVES_PER_CONTROLLER];
    BOOLEAN          Model30;
    KTIMER           MotorTimer;
    KDPC             MotorStopDpc;
    BOOLEAN          MotorStopCanceled;
} CONTROLLER_INFO, *PCONTROLLER_INFO;


/*
 * Device extension common to both FDO and PDO
 */
typedef struct _COMMON_DEVICE_EXTENSION {
    BOOLEAN IsFDO;
    PDEVICE_OBJECT DeviceObject;
} COMMON_DEVICE_EXTENSION, *PCOMMON_DEVICE_EXTENSION;

/*
 * Device extension for the Controller FDO.
 *
 * See diagram above for the device stack organization.
 */
typedef struct _FDO_DEVICE_EXTENSION {
    COMMON_DEVICE_EXTENSION Common;

    PDEVICE_OBJECT LowerDevice;	/* The device object immediately below
				 * Controller FDO in the Controller device
				 * stack. This is usually the Controller PDO,
				 * unless there is any filter driver below
				 * us (or above the lower bus driver). */
    PDEVICE_OBJECT Pdo;		/* Controller PDO. This is the lowest device
				 * object in the Controller device stack.
				 * Assuming no filter driver is present in
				 * the stack this is immediately below us. */

    CONTROLLER_INFO ControllerInfo;
} FDO_DEVICE_EXTENSION, *PFDO_DEVICE_EXTENSION;

/*
 * Device extension for the Drive PDO. See diagram above for device stack.
 */
typedef struct _PDO_DEVICE_EXTENSION {
    COMMON_DEVICE_EXTENSION Common;

    PDEVICE_OBJECT Fdo;		/* This is the Controller FDO that created
				 * this Drive PDO, as a result of the PNP
				 * IRP QueryBusRelations. */
    PDRIVE_INFO DriveInfo;

    UNICODE_STRING DeviceDescription;	// REG_SZ
    UNICODE_STRING DeviceId;		// REG_SZ
    UNICODE_STRING InstanceId;		// REG_SZ
    UNICODE_STRING HardwareIds;		// REG_MULTI_SZ
    UNICODE_STRING CompatibleIds;	// REG_MULTI_SZ
} PDO_DEVICE_EXTENSION, *PPDO_DEVICE_EXTENSION;

#define FDC_TAG 'acdF'

/* fdo.c */
NTSTATUS FdcFdoPnp(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
NTSTATUS WaitForControllerInterrupt(PCONTROLLER_INFO ControllerInfo,
				    PLARGE_INTEGER Timeout);
VOID StartMotor(PDRIVE_INFO DriveInfo);
VOID StopMotor(PCONTROLLER_INFO ControllerInfo);
NTSTATUS Recalibrate(PDRIVE_INFO DriveInfo);

/* pdo.c */
NTSTATUS FdcPdoPnp(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);

/* rw.h */
VOID ReadWrite(PDRIVE_INFO DriveInfo, PIRP Irp);
NTSTATUS RWDetermineMediaType(PDRIVE_INFO DriveInfo, BOOLEAN OneShot);
NTSTATUS SignalMediaChanged(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS ResetChangeFlag(PDRIVE_INFO DriveInfo);

/* ioctl.h */
VOID DeviceIoctl(PDRIVE_INFO DriveInfo, PIRP Irp);

#include "hw.h"
