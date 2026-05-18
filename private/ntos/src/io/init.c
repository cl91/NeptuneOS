#include "iop.h"

/* Organizes all driver objects into an AVL tree with driver process address as key */
AVL_TREE IopDriverObjectTree;
LIST_ENTRY IopShutdownNotificationList;

NTSTATUS IoInitSystemPhase0()
{
    AvlInitializeTree(&IopDriverObjectTree);
    InitializeListHead(&IopShutdownNotificationList);
    InitializeListHead(&IoBugcheckNotificationList);
    IopInitIrpProcessing();
    RET_ERR(IopCreateFileType());
    RET_ERR(IopCreateDeviceType());
    RET_ERR(IopCreateDriverType());
    RET_ERR(ObCreateDirectory(DRIVER_OBJECT_DIRECTORY));
    RET_ERR(ObCreateDirectory(DEVICE_OBJECT_DIRECTORY));
    RET_ERR(ObCreateDirectory(FILE_SYSTEM_OBJECT_DIRECTORY));
    RET_ERR(CcInitializeCacheManager());
    RET_ERR(IopInitPnpManager());

    return STATUS_SUCCESS;
}

NTSTATUS IoInitSystemPhase1()
{
    RET_ERR(IopInitFileSystem());

    return STATUS_SUCCESS;
}
