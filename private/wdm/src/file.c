#include <wdmp.h>

NTAPI VOID IoRegisterFileSystem(IN PDEVICE_OBJECT DeviceObject)
{
}

NTAPI PFILE_OBJECT IoCreateStreamFileObject(IN OPTIONAL PFILE_OBJECT FileObject,
					    IN OPTIONAL PDEVICE_OBJECT DeviceObject)
{
    /* UNIMPLEMENTED */
    assert(FALSE);
    return NULL;
}
