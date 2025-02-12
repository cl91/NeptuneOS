#include <wdmp.h>

#if defined(_M_IX86) || defined(_M_AMD64)

LIST_ENTRY IopX86PortList;

static PX86_IOPORT IopEnableIoPort(USHORT PortNum, USHORT Len)
{
    Len /= 8;
    LoopOverList(Entry, &IopX86PortList, X86_IOPORT, Link) {
	if (Entry->PortNum == PortNum && Entry->Count == Len) {
	    return Entry;
	}
    }
    PX86_IOPORT IoPort = ExAllocatePool(sizeof(X86_IOPORT));
    if (!IoPort) {
	return NULL;
    }
    MWORD Cap = 0;
    NTSTATUS Status = WdmEnableX86Port(PortNum, Len, &Cap);
    if (!NT_SUCCESS(Status)) {
	IopFreePool(IoPort);
	return NULL;
    }
    IoPort->Cap = Cap;
    IoPort->PortNum = PortNum;
    IoPort->Count = Len;
    InsertTailList(&IopX86PortList, &IoPort->Link);
    return IoPort;
}

#define DEFINE_READ_PORT_HELPER(Len, Type)			\
    static NTSTATUS IopReadPort##Len(IN PX86_IOPORT Port,	\
				     OUT Type *Out)		\
    {								\
	assert(Out != NULL);					\
	seL4_X86_IOPort_In##Len##_t Reply =			\
	    seL4_X86_IOPort_In##Len(Port->Cap, Port->PortNum);	\
	if (Reply.error != 0) {					\
	    DbgTrace("Reading IO port 0x%x (cap 0x%zx) failed "	\
		     "with error %d\n",				\
		     Port->PortNum, Port->Cap, Reply.error);	\
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
	int Error = seL4_X86_IOPort_Out##Len(Port->Cap,			\
					     Port->PortNum, Data);	\
	if (Error != 0) {						\
	    DbgTrace("Writing IO port 0x%x (cap 0x%zx) with "		\
		     "data 0x%x failed with error %d\n",		\
		     Port->PortNum, Port->Cap, Data, Error);		\
	    KeDbgDumpIPCError(Error);					\
	    return SEL4_ERROR(Error);					\
	}								\
	return STATUS_SUCCESS;						\
    }

#define DEFINE_PORT_IN_FUNC(Name, Len, Type)			\
    __cdecl Type __in##Name(IN USHORT PortNum)			\
    {								\
	PX86_IOPORT Port = IopEnableIoPort(PortNum, Len);	\
	if (Port == NULL) {					\
	    RtlRaiseStatus(STATUS_UNSUCCESSFUL);		\
	}							\
	Type Value;						\
	NTSTATUS Status = IopReadPort##Len(Port, &Value);	\
	if (!NT_SUCCESS(Status)) {				\
	    RtlRaiseStatus(STATUS_UNSUCCESSFUL);		\
	}							\
	return Value;						\
    }

#define DEFINE_PORT_OUT_FUNC(Name, Len, Type)			\
    __cdecl VOID __out##Name(IN USHORT PortNum,			\
			     IN Type Data)			\
    {								\
	PX86_IOPORT Port = IopEnableIoPort(PortNum, Len);	\
	if (Port == NULL) {					\
	    RtlRaiseStatus(STATUS_UNSUCCESSFUL);		\
	}							\
	NTSTATUS Status = IopWritePort##Len(Port, Data);	\
	if (!NT_SUCCESS(Status)) {				\
	    RtlRaiseStatus(STATUS_UNSUCCESSFUL);		\
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

#endif
