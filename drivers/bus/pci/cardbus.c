/*
 * PROJECT:         ReactOS PCI Bus Driver
 * LICENSE:         BSD - See COPYING.ARM in the top level directory
 * FILE:            drivers/bus/pci/intrface/cardbus.c
 * PURPOSE:         CardBus Interface
 * PROGRAMMERS:     ReactOS Portable Systems Group
 */

/* INCLUDES *******************************************************************/

#include "pcidrv.h"

/* FUNCTIONS ******************************************************************/

VOID Cardbus_SaveCurrentSettings(IN PPCI_CONFIGURATOR_CONTEXT Context)
{
    UNREFERENCED_PARAMETER(Context);
    UNIMPLEMENTED_DBGBREAK();
}

VOID Cardbus_SaveLimits(IN PPCI_CONFIGURATOR_CONTEXT Context)
{
    UNREFERENCED_PARAMETER(Context);
    UNIMPLEMENTED_DBGBREAK();
}

VOID Cardbus_MassageHeaderForLimitsDetermination(IN PPCI_CONFIGURATOR_CONTEXT Context)
{
    UNREFERENCED_PARAMETER(Context);
    UNIMPLEMENTED_DBGBREAK();
}

VOID Cardbus_RestoreCurrent(IN PPCI_CONFIGURATOR_CONTEXT Context)
{
    UNREFERENCED_PARAMETER(Context);
    UNIMPLEMENTED_DBGBREAK();
}

VOID Cardbus_GetAdditionalResourceDescriptors(IN PPCI_CONFIGURATOR_CONTEXT Context,
					      IN PPCI_COMMON_HEADER PciData,
					      IN PIO_RESOURCE_DESCRIPTOR IoDescriptor)
{
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(PciData);
    UNREFERENCED_PARAMETER(IoDescriptor);
    UNIMPLEMENTED_DBGBREAK();
}

VOID Cardbus_ResetDevice(IN PPCI_PDO_EXTENSION PdoExtension,
			 IN PPCI_COMMON_HEADER PciData)
{
    UNREFERENCED_PARAMETER(PdoExtension);
    UNREFERENCED_PARAMETER(PciData);
    UNIMPLEMENTED_DBGBREAK();
}

VOID Cardbus_ChangeResourceSettings(IN PPCI_PDO_EXTENSION PdoExtension,
				    IN PPCI_COMMON_HEADER PciData)
{
    UNREFERENCED_PARAMETER(PdoExtension);
    UNREFERENCED_PARAMETER(PciData);
    UNIMPLEMENTED_DBGBREAK();
}
