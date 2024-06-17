#include "halp.h"

HAL_ACPI_RSDP HalpAcpiRsdp;

VOID HalAcpiRegisterRsdp(IN PHAL_ACPI_RSDP Rsdp)
{
    HalpAcpiRsdp = *Rsdp;
}

CM_PARTIAL_RESOURCE_DESCRIPTOR HalAcpiGetRsdtResource()
{
    assert(HalpAcpiRsdp.XsdtAddress || HalpAcpiRsdp.RsdtAddress);
    ULONG64 Address = HalpAcpiRsdp.XsdtAddress ?
	HalpAcpiRsdp.XsdtAddress : HalpAcpiRsdp.RsdtAddress;
    /* Inform the client of whether we got an RSDT or an XSDT. If we are running
     * on a BIOS with ACPI 1.0 (or if the XSDT address is NULL, which for ACPI >= 2.0
     * is a violation of the ACPI specs), we have an RSDT. Otherwise it's an XSDT. */
    ULONG Length = HalpAcpiRsdp.XsdtAddress && HalpAcpiRsdp.Revision ? 8 : 4;
    CM_PARTIAL_RESOURCE_DESCRIPTOR Rsdt = {
	.Type = CmResourceTypeMemory,
	.u.Memory = {
	    .Start.QuadPart = Address,
	    .Length = Length
	}
    };
    return Rsdt;
}

VOID HalAcpiDumpRsdp(IN PHAL_ACPI_RSDP Rsdp, IN ULONG Indentation)
{
    RtlDbgPrintIndentation(Indentation);
    DbgPrint("RSDP %p\n", Rsdp);
    RtlDbgPrintIndentation(Indentation);
    DbgPrint("Signature %c%c%c%c%c%c%c%c\n", Rsdp->Signature[0],
	     Rsdp->Signature[1], Rsdp->Signature[2], Rsdp->Signature[3],
	     Rsdp->Signature[4], Rsdp->Signature[5], Rsdp->Signature[6],
	     Rsdp->Signature[7]);
    RtlDbgPrintIndentation(Indentation);
    DbgPrint("Checksum 0x%x\n", Rsdp->Checksum);
    RtlDbgPrintIndentation(Indentation);
    DbgPrint("OEMId %c%c%c%c%c%c\n", Rsdp->OemId[0],
	     Rsdp->OemId[1], Rsdp->OemId[2], Rsdp->OemId[3],
	     Rsdp->OemId[4], Rsdp->OemId[5]);
    RtlDbgPrintIndentation(Indentation);
    DbgPrint("Revision %d\n", Rsdp->Revision);
    RtlDbgPrintIndentation(Indentation);
    DbgPrint("RSDT Physical Address 0x%x\n", Rsdp->RsdtAddress);
    RtlDbgPrintIndentation(Indentation);
    DbgPrint("RSDT Length 0x%x\n", Rsdp->Length);
    RtlDbgPrintIndentation(Indentation);
    DbgPrint("XSDT Physical Address 0x%llx\n", Rsdp->XsdtAddress);
    RtlDbgPrintIndentation(Indentation);
    DbgPrint("Extended Checksum 0x%x\n", Rsdp->ExtendedChecksum);
}
