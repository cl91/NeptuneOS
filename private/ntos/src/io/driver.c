#include "iop.h"

NTSTATUS IoLoadDriver(IN PCSTR DriverToLoad)
{
    PFILE_OBJECT DriverFile = NULL;
    RET_ERR(ObReferenceObjectByName(DriverToLoad, (POBJECT *) &DriverFile));
    assert(DriverFile != NULL);

    PPROCESS Process = NULL;
    RET_ERR(PsCreateProcess(DriverFile, PROC_CREA_FLAG_DRIVER, &Process));
    assert(Process != NULL);

    RET_ERR_EX(PsLoadDll(Process, HAL_DLL_NAME),
	       ObDeleteObject(Process));

    PTHREAD Thread = NULL;
    RET_ERR_EX(PsCreateThread(Process, &Thread),
	       ObDeleteObject(Process));
    assert(Thread != NULL);
    return STATUS_SUCCESS;
}

NTSTATUS NtLoadDriver(IN PTHREAD Thread,
		      IN PCSTR DriverServiceName)
{
    RET_ERR(IoLoadDriver(DriverServiceName));
    return STATUS_SUCCESS;
}
