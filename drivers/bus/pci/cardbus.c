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

VOID Cardbus_MassageHeaderForLimitsDetermination(OUT PPCI_COMMON_HEADER Cfg)
{
    UNREFERENCED_PARAMETER(Cfg);
    UNIMPLEMENTED_DBGBREAK();
}

VOID Cardbus_ReadResources(IN PPCI_PDO_EXTENSION PdoExt,
			   OUT PPCI_COMMON_HEADER Cfg)
{
    UNREFERENCED_PARAMETER(PdoExt);
    UNREFERENCED_PARAMETER(Cfg);
    UNIMPLEMENTED_DBGBREAK();
}

VOID Cardbus_WriteResources(IN PPCI_PDO_EXTENSION PdoExt,
			    IN PPCI_COMMON_HEADER Cfg)
{
    UNREFERENCED_PARAMETER(Cfg);
    UNIMPLEMENTED_DBGBREAK();
    /*
     * At offset 44h the LegacyBaseAddress is stored, which is cleared by
     * ACPI-aware versions of Windows, to disable legacy-mode I/O access to
     * CardBus controllers. For more information, see "Supporting CardBus
     * Controllers under ACPI" in the "CardBus Controllers and Windows"
     * Whitepaper on WHDC.
     */
    ULONG LegacyBaseAddress = 0;
    PciWriteDeviceConfig(PdoExt, &LegacyBaseAddress,
			 sizeof(PCI_COMMON_HEADER) + sizeof(ULONG), sizeof(ULONG));
}

VOID Cardbus_SaveLimits(IN PPCI_PDO_EXTENSION PdoExtension,
			IN PPCI_COMMON_HEADER Cfg)
{
    UNREFERENCED_PARAMETER(PdoExtension);
    UNREFERENCED_PARAMETER(Cfg);
    UNIMPLEMENTED_DBGBREAK();
}

VOID Cardbus_SaveCurrentSettings(IN PPCI_PDO_EXTENSION PdoExtension,
				 IN PPCI_COMMON_HEADER Cfg)
{
    UNREFERENCED_PARAMETER(PdoExtension);
    UNREFERENCED_PARAMETER(Cfg);
    UNIMPLEMENTED_DBGBREAK();
}

VOID Cardbus_GetAdditionalResourceDescriptors(IN PPCI_PDO_EXTENSION PdoExt,
					      IN PIO_RESOURCE_DESCRIPTOR IoDescriptor)
{
    UNREFERENCED_PARAMETER(IoDescriptor);
    UNIMPLEMENTED_DBGBREAK();
}

VOID Cardbus_ResetDevice(IN PPCI_PDO_EXTENSION PdoExtension)
{
    UNREFERENCED_PARAMETER(PdoExtension);
    UNIMPLEMENTED_DBGBREAK();
}

VOID Cardbus_ChangeResourceSettings(IN PPCI_PDO_EXTENSION PdoExtension,
				    OUT USHORT *CommandEnables)
{
    UNREFERENCED_PARAMETER(PdoExtension);
    UNREFERENCED_PARAMETER(CommandEnables);
    UNIMPLEMENTED_DBGBREAK();
}
