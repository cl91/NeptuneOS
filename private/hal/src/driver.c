#include <halp.h>

/*
 * @implemented
 *
 * Allocates a per-driver context area and assigns a unique identifier to it.
 * The per-driver context area follows the header IO_CLIENT_EXTENSION which
 * records the identifier and chains all extensions of one driver. The pointer
 * to the beginning of the per-driver context area (ie. the memory immediately
 * after the header) is returned via pDriverExtension.
 */
NTAPI NTSTATUS IoAllocateDriverObjectExtension(IN PDRIVER_OBJECT DriverObject,
					       IN PVOID ClientIdentAddr,
					       IN ULONG DriverExtensionSize,
					       OUT PVOID *pDriverExtension)
{
    /* Assume failure */
    *pDriverExtension = NULL;

    /* Make sure client indentification address is not already used */
    for (PIO_CLIENT_EXTENSION DrvExt = DriverObject->ClientDriverExtension;
	 DrvExt != NULL; DrvExt = DrvExt->NextExtension) {
        /* Check if the identifier matches */
        if (DrvExt->ClientIdentificationAddress == ClientIdentAddr) {
            /* We have a collision, return error */
            return STATUS_OBJECT_NAME_COLLISION;
        }
    }

    /* Allocate the driver extension */
    PIO_CLIENT_EXTENSION DrvExt = ExAllocatePoolWithTag(sizeof(IO_CLIENT_EXTENSION)
							+ DriverExtensionSize,
							TAG_DRIVER_EXTENSION);
    if (!DrvExt) {
	return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* Fill out the extension and add it to the driver's client extension list */
    DrvExt->ClientIdentificationAddress = ClientIdentAddr;
    DrvExt->NextExtension =DriverObject->ClientDriverExtension;
    DriverObject->ClientDriverExtension = DrvExt;

    /* Return the pointer to the memory immediately after the header */
    *pDriverExtension = DrvExt + 1;
    return STATUS_SUCCESS;
}

/*
 * @implemented
 *
 * Returns the pointer to the beginning of the per-driver context area
 * (ie. the memory immediately after the header) matching the given identifer.
 */
NTAPI PVOID IoGetDriverObjectExtension(IN PDRIVER_OBJECT DriverObject,
				       IN PVOID ClientIdentAddr)
{
    /* Loop the list until we find the right one */
    for (PIO_CLIENT_EXTENSION DrvExt = DriverObject->ClientDriverExtension;
	 DrvExt != NULL; DrvExt = DrvExt->NextExtension) {
        /* Check if the identifier matches */
        if (DrvExt->ClientIdentificationAddress == ClientIdentAddr) {
	    /* Return the pointer to the memory immediately after the header */
	    return DrvExt + 1;
        }
    }
    return NULL;
}

/*
 * @implemented
 */
NTAPI VOID IoRegisterDriverReinitialization(IN PDRIVER_OBJECT DriverObject,
					    IN PDRIVER_REINITIALIZE ReinitRoutine,
					    IN PVOID Context)
{
    /* Allocate the entry */
    PDRIVER_REINIT_ITEM ReinitItem = ExAllocatePoolWithTag(sizeof(DRIVER_REINIT_ITEM),
							   TAG_REINIT);
    if (!ReinitItem) {
	return;
    }

    /* Fill it out */
    ReinitItem->DriverObject = DriverObject;
    ReinitItem->ReinitRoutine = ReinitRoutine;
    ReinitItem->Context = Context;

    /* Set the Driver Object flag and insert the entry into the list */
    DriverObject->Flags |= DRVO_REINIT_REGISTERED;
    InsertTailList(&DriverObject->ReinitListHead, &ReinitItem->ItemEntry);
}
