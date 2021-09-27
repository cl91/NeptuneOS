#include "iop.h"

NTSTATUS IopFileObjectOpenProc(POBJECT Object)
{
    return STATUS_SUCCESS;
}

NTSTATUS NtOpenFile(IN PTHREAD Thread,
                    OUT HANDLE *FileHandle,
                    IN ACCESS_MASK DesiredAccess,
                    IN OB_OBJECT_ATTRIBUTES ObjectAttributes,
                    OUT IO_STATUS_BLOCK *IoStatusBlock,
                    IN ULONG ShareAccess,
                    IN ULONG OpenOptions)
{
    return STATUS_NOT_IMPLEMENTED;
}
