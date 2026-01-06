#include <ntlnxdrv.h>

LNX_DRV_ENTRY_POINT LnxDriverEntry;

static PLNX_DRV_IMPORT_TABLE LnxDrvImportTable;

static VOID Exp0()
{
    LnxDrvImportTable->DbgPrint("Hello from export table\n");
}

static LNX_DRV_EXPORT_TABLE LnxDrvExportTable = {
    .Exp0 = Exp0
};

NTSTATUS LnxDriverEntry(IN PLNX_DRV_IMPORT_TABLE ImportTable,
			OUT PLNX_DRV_EXPORT_TABLE *ExportTable)
{
    LnxDrvImportTable = ImportTable;
    *ExportTable = &LnxDrvExportTable;
    return STATUS_SUCCESS;
}
