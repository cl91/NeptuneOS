#include "halp.h"

HAL_ACPI_RSDP HalpAcpiRsdp;

VOID HalAcpiRegisterRsdp(IN PHAL_ACPI_RSDP Rsdp)
{
    HalpAcpiRsdp = *Rsdp;
}

CM_PARTIAL_RESOURCE_DESCRIPTOR HalAcpiGetRsdtResource()
{
    CM_PARTIAL_RESOURCE_DESCRIPTOR Rsdt = {
	.Type = CmResourceTypeMemory,
	.u.Memory = {
	    .Start.QuadPart = HalpAcpiRsdp.XsdtAddress,
	    .Length = HalpAcpiRsdp.Length
	}
    };
    return Rsdt;
}
