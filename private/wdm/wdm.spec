@ stdcall IoCreateDevice(ptr long ptr long int64 long ptr)
@ stdcall IoCreateStreamFileObject(ptr)
@ stdcall IoRegisterDriverReinitialization(ptr ptr ptr)
@ stdcall IoAllocateDriverObjectExtension(ptr ptr long ptr)
@ stdcall IoRegisterFileSystem(ptr)
@ stdcall IoGetDriverObjectExtension(ptr ptr)
@ stdcall IoGetDeviceObjectPointer(ptr long ptr ptr)
@ stdcall IoAttachDeviceToDeviceStack(ptr ptr)
@ stdcall IoGetAttachedDevice(ptr)
@ stdcall IoGetAttachedDeviceReference(ptr)
@ stdcall IoRegisterDeviceInterface(ptr ptr ptr ptr)
@ stdcall IoSetDeviceInterfaceState(ptr long)
@ stdcall IoGetDeviceInterfaces(ptr ptr long ptr)
@ stdcall IoGetDeviceProperty(ptr long long ptr ptr)
@ stdcall IoCreateSymbolicLink(ptr ptr)
@ stdcall IoOpenDeviceRegistryKey(ptr long long ptr)
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
@ stdcall IoCancelIrp(ptr)
@ stdcall IoConnectInterrupt(ptr ptr ptr long long long long long long long)
@ stdcall IoDisconnectInterrupt(ptr)
@ stdcall IoAllocateWorkItem(ptr)
@ stdcall IoFreeWorkItem(ptr)
@ stdcall IoQueueWorkItem(ptr ptr long ptr)
@ stdcall IoAcquireInterruptMutex(ptr)
@ stdcall IoReleaseInterruptMutex(ptr long)
@ stdcall IoRegisterPlugPlayNotification(long long ptr ptr ptr ptr ptr)
@ stdcall IoWMIRegistrationControl(ptr long)
@ stdcall PoSetPowerState(ptr long long)
@ stdcall PoRequestPowerIrp(ptr long long ptr ptr ptr)
@ stdcall MmPageEntireDriver(ptr)
@ stdcall MmMapIoSpace(long long long long)
@ stdcall MmUnmapIoSpace(ptr long)
@ stdcall MmGetPhysicalAddress(ptr)
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
@ stdcall -arch=arm KeFlushIoBuffers(ptr long long)
@ stdcall ObDereferenceObject(ptr)
@ stdcall HalMakeBeep(long)
@ stdcall HalGetAdapter(ptr ptr)
@ stdcall CcInitializeCacheMap(ptr)
@ stdcall CcUninitializeCacheMap(ptr ptr)
@ stdcall CcMapData(ptr ptr long long ptr ptr ptr)
@ stdcall CcSetDirtyData(ptr)
@ stdcall CcUnpinData(ptr)
@ stdcall CcCopyRead(ptr ptr long long ptr ptr)
@ stdcall CcCopyWrite(ptr ptr long long ptr ptr)
@ stdcall CcMdlRead(ptr ptr long ptr ptr)
@ stdcall CcSetFileSizes(ptr ptr)
@ stdcall CcFlushCache(ptr ptr long ptr)
@ stdcall FsRtlDoesNameContainWildCards(ptr)
@ stdcall FsRtlIsNameInExpression(ptr ptr long wstr)
@ stdcall FsRtlAreNamesEqual(ptr ptr long wstr)
@ cdecl -arch=i386,x86_64 __inbyte(long)
@ cdecl -arch=i386,x86_64 __outbyte(long long)
@ cdecl -arch=i386,x86_64 __inword(long)
@ cdecl -arch=i386,x86_64 __outword(long long)
@ cdecl -arch=i386,x86_64 __indword(long)
@ cdecl -arch=i386,x86_64 __outdword(long long)
@ cdecl _assert(str str long)
