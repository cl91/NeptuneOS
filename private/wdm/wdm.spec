@ stdcall IoCreateDevice(ptr long ptr long long long ptr)
@ stdcall IoCreateStreamFileObject(ptr)
@ stdcall IoRegisterDriverReinitialization(ptr ptr ptr)
@ stdcall IoAllocateDriverObjectExtension(ptr ptr long ptr)
@ stdcall IoRegisterFileSystem(ptr)
@ stdcall IoGetDriverObjectExtension(ptr ptr)
@ stdcall IoGetDeviceObjectPointer(ptr long ptr ptr)
@ stdcall IoAttachDeviceToDeviceStack(ptr ptr)
@ stdcall IoGetAttachedDevice(ptr)
@ stdcall IoRegisterDeviceInterface(ptr ptr ptr ptr)
@ stdcall IoSetDeviceInterfaceState(ptr long)
@ stdcall IoQueryDeviceDescription(ptr ptr ptr ptr ptr ptr ptr ptr)
@ stdcall IoDetachDevice(ptr)
@ stdcall IoDeleteDevice(ptr)
@ stdcall IoStartPacket(ptr ptr ptr ptr)
@ stdcall IoStartNextPacket(ptr long)
@ stdcall IoBuildDeviceIoControlRequest(long ptr ptr long ptr long long ptr)
@ stdcall IoBuildAsynchronousFsdRequest(long ptr ptr long ptr)
@ stdcall IoBuildSynchronousFsdRequest(long ptr ptr long ptr ptr)
@ stdcall IoCallDriverEx(ptr ptr ptr)
@ stdcall IoCompleteRequest(ptr long)
@ stdcall IoConnectInterrupt(ptr ptr ptr long long long long long long long)
@ stdcall IoDisconnectInterrupt(ptr)
@ stdcall IoAllocateWorkItem(ptr)
@ stdcall IoFreeWorkItem(ptr)
@ stdcall IoQueueWorkItem(ptr ptr long ptr)
@ stdcall IoAcquireInterruptMutex(ptr)
@ stdcall IoReleaseInterruptMutex(ptr long)
@ stdcall MmPageEntireDriver(ptr)
@ stdcall KeInsertDeviceQueue(ptr ptr)
@ stdcall KeInsertByKeyDeviceQueue(ptr ptr long)
@ stdcall KeRemoveDeviceQueue(ptr)
@ stdcall KeRemoveByKeyDeviceQueue(ptr long)
@ stdcall KeInsertQueueDpc(ptr ptr ptr)
@ stdcall KeInitializeTimer(ptr)
@ stdcall KeSetTimer(ptr long long ptr ptr)
@ stdcall KeQueryInterruptTime()
@ stdcall KeDelayExecutionThread(long ptr)
@ stdcall KeStallExecutionProcessor(long)
@ stdcall KeInitializeEvent(ptr long long)
@ stdcall KeSetEvent(ptr)
@ stdcall KeResetEvent(ptr)
@ stdcall KeClearEvent(ptr)
@ stdcall HalMakeBeep(long)
@ stdcall HalGetAdapter(ptr ptr)
@ stdcall CcInitializeCacheMap(ptr ptr long ptr ptr)
@ stdcall CcUninitializeCacheMap(ptr ptr ptr)
@ stdcall CcPinRead(ptr ptr long long ptr ptr)
@ stdcall CcSetDirtyPinnedData(ptr ptr)
@ stdcall CcUnpinData(ptr)
@ stdcall CcZeroData(ptr ptr ptr long)
@ stdcall CcSetFileSizes(ptr ptr)
@ stdcall FsRtlDoesNameContainWildCards(ptr)
@ stdcall FsRtlIsNameInExpression(ptr ptr long wstr)
@ stdcall FsRtlAreNamesEqual(ptr ptr long wstr)
@ cdecl __inbyte(long)
@ cdecl __outbyte(long long)
@ cdecl _assert(str str long)
