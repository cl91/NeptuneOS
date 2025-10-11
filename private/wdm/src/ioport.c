#include <wdmp.h>

#if defined(_M_IX86) || defined(_M_AMD64)

/* This list is accessed by both the ISR and non-ISR code, so we must synchronize access. */
SLIST_HEADER IopX86PortList;

static NTSTATUS IopEnableIoPort(IN USHORT PortNum,
				IN USHORT Len,
				OUT PX86_IOPORT *pIoPort)
{
    Len /= 8;
    PSLIST_ENTRY Entry = RtlFirstEntrySList(&IopX86PortList);
    while (Entry) {
	PX86_IOPORT Port = CONTAINING_RECORD(Entry, X86_IOPORT, Link);
	if (Port->PortNum == PortNum) {
	    if (Port->Count == Len) {
		*pIoPort = Port;
		return STATUS_SUCCESS;
	    } else {
		return STATUS_ALREADY_INITIALIZED;
	    }
	}
	Entry = Entry->Next;
    }
    if (!IoThreadIsAtPassiveLevel()) {
	assert(FALSE);
	return STATUS_INVALID_THREAD;
    }
    PX86_IOPORT IoPort = ExAllocatePool(NonPagedPool, sizeof(X86_IOPORT));
    if (!IoPort) {
	return STATUS_INSUFFICIENT_RESOURCES;
    }
    MWORD Cap = 0;
    NTSTATUS Status = WdmEnableX86Port(PortNum, Len, &Cap);
    if (!NT_SUCCESS(Status)) {
	IopFreePool(IoPort);
	return Status;
    }
    IoPort->Cap = Cap;
    IoPort->PortNum = PortNum;
    IoPort->Count = Len;
    RtlInterlockedPushEntrySList(&IopX86PortList, &IoPort->Link);
    *pIoPort = IoPort;
    return STATUS_SUCCESS;
}

#define DEFINE_READ_PORT_HELPER(Len, Type)			\
    static NTSTATUS IopReadPort##Len(IN PX86_IOPORT Port,	\
				     OUT Type *Out)		\
    {								\
	assert(Out != NULL);					\
	MWORD Cap = RtlGetGuardedCapInProcessCNode(Port->Cap);	\
	seL4_X86_IOPort_In##Len##_t Reply =			\
	    seL4_X86_IOPort_In##Len(Cap, Port->PortNum);	\
	if (Reply.error != 0) {					\
	    DbgTrace("Reading IO port 0x%x (cap 0x%zx) failed "	\
		     "with error %d\n",				\
		     Port->PortNum, Cap, Reply.error);		\
	    KeDbgDumpIPCError(Reply.error);			\
	    return SEL4_ERROR(Reply.error);			\
	}							\
	*Out = Reply.result;					\
	return STATUS_SUCCESS;					\
    }								\

#define DEFINE_WRITE_PORT_HELPER(Len, Type)				\
    static NTSTATUS IopWritePort##Len(IN PX86_IOPORT Port,		\
				      IN Type Data)			\
    {									\
	MWORD Cap = RtlGetGuardedCapInProcessCNode(Port->Cap);		\
	int Error = seL4_X86_IOPort_Out##Len(Cap, Port->PortNum, Data);	\
	if (Error != 0) {						\
	    DbgTrace("Writing IO port 0x%x (cap 0x%zx) with "		\
		     "data 0x%x failed with error %d\n",		\
		     Port->PortNum, Cap, Data, Error);			\
	    KeDbgDumpIPCError(Error);					\
	    return SEL4_ERROR(Error);					\
	}								\
	return STATUS_SUCCESS;						\
    }

#define DEFINE_PORT_IN_FUNC(Name, Len, Type)			\
    __cdecl Type __in##Name(IN USHORT PortNum)			\
    {								\
	PX86_IOPORT Port = NULL;				\
	NTSTATUS Status = IopEnableIoPort(PortNum, Len, &Port);	\
	if (Port == NULL) {					\
	    RtlRaiseStatus(Status);				\
	}							\
	Type Value;						\
	Status = IopReadPort##Len(Port, &Value);		\
	if (!NT_SUCCESS(Status)) {				\
	    RtlRaiseStatus(Status);				\
	}							\
	return Value;						\
    }

#define DEFINE_PORT_OUT_FUNC(Name, Len, Type)			\
    __cdecl VOID __out##Name(IN USHORT PortNum,			\
			     IN Type Data)			\
    {								\
	PX86_IOPORT Port = NULL;				\
	NTSTATUS Status = IopEnableIoPort(PortNum, Len, &Port);	\
	if (Port == NULL) {					\
	    RtlRaiseStatus(Status);				\
	}							\
	Status = IopWritePort##Len(Port, Data);			\
	if (!NT_SUCCESS(Status)) {				\
	    RtlRaiseStatus(Status);				\
	}							\
    }

DEFINE_READ_PORT_HELPER(8, UCHAR);
DEFINE_WRITE_PORT_HELPER(8, UCHAR);
DEFINE_PORT_IN_FUNC(byte, 8, UCHAR);
DEFINE_PORT_OUT_FUNC(byte, 8, UCHAR);
DEFINE_READ_PORT_HELPER(16, USHORT);
DEFINE_WRITE_PORT_HELPER(16, USHORT);
DEFINE_PORT_IN_FUNC(word, 16, USHORT);
DEFINE_PORT_OUT_FUNC(word, 16, USHORT);
DEFINE_READ_PORT_HELPER(32, ULONG);
DEFINE_WRITE_PORT_HELPER(32, ULONG);
DEFINE_PORT_IN_FUNC(dword, 32, ULONG);
DEFINE_PORT_OUT_FUNC(dword, 32, ULONG);

NTAPI NTSTATUS IoEnablePort(IN USHORT PortNum,
			    IN USHORT Len)
{
    if (!(Len == 8 || Len == 16 || Len == 32)) {
	return STATUS_INVALID_PARAMETER_2;
    }
    PX86_IOPORT Port = NULL;
    return IopEnableIoPort(PortNum, Len, &Port);
}

#else

NTAPI NTSTATUS IoEnablePort(IN USHORT PortNum,
			    IN USHORT Len)
{
    return STATUS_NOT_SUPPORTED;
}

#endif
