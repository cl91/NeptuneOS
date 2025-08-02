/*++

Copyright (C) Microsoft Corporation, 1990 - 1998

Module Name:

    lock.c

Abstract:

    This is the NT SCSI port driver.

Environment:

    kernel mode only

Notes:

    This module is a driver dll for scsi miniports.

Revision History:

--*/

#include "classp.h"
#include "debug.h"

/*++////////////////////////////////////////////////////////////////////////////

Classpnp RemoveLockRundown

RemoveLockRundown is a cacheaware rundown protection for the classpnp device object. While this
rundown protection is held successfully, the caller can assume that no pending pnp REMOVE
requests will be completed.

The RemoveLockRundown is a replacement of the original RemoveLock to improve the scalability.
For backward compatibility, we still keep the RemoveLock field in the device common extension structure.
However, the old RemoveLock is only being used in the DBG build.

The usage of the RemoveLockRundown is slightly different from the normal rundown protection usage.
The RemoveLockRundown is acquired via ClassAcquireRemoveLockEx() function
and released via ClassReleaseRemoveLock() function. Usually, we bail out when the acquisition
of rundown protection fails (calls to ExAcquireRundownProtectionCacheAware returns FALSE) and
will not release the rundown protection in acquisition failure. For the RemoveLockRundown,
the caller will always call ClassAcquireRemoveLockEx() and ClassReleaseRemoveLock() in a pair no
matter the return value of ClassAcquireRemoveLockEx(). Therefore, a thread may still call
ClassReleaseRemoveLock() even the previous acquisition RemoveLockRundown protection failed.

To deal with the previous acquisition failure case, we introduced a new field RemoveLockFailAcquire
as a counter for rundown acquisition failures. In the ClassReleaseRemoveLock() function, we only
release the rundown protection when this counter is decremented to zero. Since the change of RemoveLockFailAcquire
and release rundown protection is not protected by a lock as an atomic operation, we use a while loop over
InterlockedCompareExchange operation to make sure when we release the rundown protection, this counter is
actually zero.

--*/

/*++////////////////////////////////////////////////////////////////////////////

ClassAcquireRemoveLockEx()

Routine Description:

    This routine is called to acquire the remove lock on the device object.
    While the lock is held, the caller can assume that no pending pnp REMOVE
    requests will be completed.

    The lock should be acquired immediately upon entering a dispatch routine.
    It should also be acquired before creating any new reference to the
    device object if there's a chance of releasing the reference before the
    new one is done.

    This routine will return TRUE if the lock was successfully acquired or
    FALSE if it cannot be because the device object has already been removed.

Neptune OS Notes:

    Since on Neptune OS dispatch routines cannot be preempted, we simply return
    the IsRemoved flag. No locking is actually required.

Arguments:

    DeviceObject - the device object to lock

    Tag - Used for tracking lock allocation and release.  If an irp is
          specified when acquiring the lock then the same Tag must be
          used to release the lock before the Tag is completed.

Return Value:

    The value of the IsRemoved flag in the device extension.  If this is
    non-zero then the device object has received a Remove irp and non-cleanup
    IRP's should fail.

    If the value is REMOVE_COMPLETE, the caller should not even release the
    lock.

--*/
NTAPI ULONG ClassAcquireRemoveLockEx(IN PDEVICE_OBJECT DeviceObject, IN PVOID Tag,
				     IN PCSTR File, IN ULONG Line)
// This function implements the acquisition of Tag
{
    PCOMMON_DEVICE_EXTENSION commonExtension = DeviceObject->DeviceExtension;
    return commonExtension->IsRemoved;
}

/*++////////////////////////////////////////////////////////////////////////////

ClassReleaseRemoveLock()

Routine Description:

    This routine is called to release the remove lock on the device object.  It
    must be called when finished using a previously locked reference to the
    device object.  If an Tag was specified when acquiring the lock then the
    same Tag must be specified when releasing the lock.

    When the lock count reduces to zero, this routine will signal the waiting
    remove Tag to delete the device object.  As a result the DeviceObject
    pointer should not be used again once the lock has been released.

Neptune OS Note:

    Since on Neptune OS dispatch routines cannot be preempted, no locking is
    required, so this routine does nothing.

Arguments:

    DeviceObject - the device object to lock

    Tag - The irp (if any) specified when acquiring the lock.  This is used
          for lock tracking purposes

Return Value:

    none

Note:
    This function implements the release of Tag

--*/
NTAPI VOID ClassReleaseRemoveLock(IN PDEVICE_OBJECT DeviceObject,
				  IN OPTIONAL PIRP Tag)
{
    /* Do nothing */
}

/*++////////////////////////////////////////////////////////////////////////////

ClassCompleteRequest()

Routine Description:

    This routine is a wrapper around (and should be used instead of)
    IoCompleteRequest.  It is used primarily for debugging purposes.
    The routine will assert if the Irp being completed is still holding
    the release lock.

Arguments:

    DeviceObject - the device object that was handling this request

    Irp - the irp to be completed by IoCompleteRequest

    PriorityBoost - the priority boost to pass to IoCompleteRequest

Return Value:

    none

--*/
NTAPI VOID ClassCompleteRequest(IN PDEVICE_OBJECT DeviceObject,
				IN PIRP Irp,
				IN CCHAR PriorityBoost)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    IoCompleteRequest(Irp, PriorityBoost);
} // end ClassCompleteRequest()
