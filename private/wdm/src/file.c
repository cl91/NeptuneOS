#include <wdmp.h>

NTAPI NTSTATUS IoRegisterFileSystem(IN PDEVICE_OBJECT DeviceObject)
{
    GLOBAL_HANDLE Handle = IopGetDeviceHandle(DeviceObject);
    if (Handle == 0) {
	return STATUS_INVALID_PARAMETER;
    }
    return IopRegisterFileSystem(Handle);
}

NTAPI PFILE_OBJECT IoCreateStreamFileObject(IN OPTIONAL PFILE_OBJECT FileObject,
					    IN OPTIONAL PDEVICE_OBJECT DeviceObject)
{
    /* UNIMPLEMENTED */
    assert(FALSE);
    return NULL;
}
