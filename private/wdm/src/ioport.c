#include <wdmp.h>

LIST_ENTRY IopX86PortList;

NTAPI NTSTATUS IoEnableX86Port(USHORT PortNum)
{
    IopAllocateObject(IoPort, X86_IOPORT);
    MWORD Cap = 0;
    RET_ERR_EX(IopEnableX86Port(PortNum, &Cap),
	       IopFreePool(IoPort));
    IoPort->Cap = Cap;
    IoPort->PortNum = PortNum;
    InsertTailList(&IopX86PortList, &IoPort->Link);
    return STATUS_SUCCESS;
}

static inline PX86_IOPORT IopFindIoPort(USHORT PortNum)
{
    LoopOverList(Entry, &IopX86PortList, X86_IOPORT, Link) {
	if (Entry->PortNum == PortNum) {
	    return Entry;
	}
    }
    return NULL;
}

static NTSTATUS IopReadPort8(IN PX86_IOPORT Port,
			     OUT UCHAR *Out)
{
    assert(Out != NULL);
    seL4_X86_IOPort_In8_t Reply = seL4_X86_IOPort_In8(Port->Cap,
						      Port->PortNum);
    if (Reply.error != 0) {
	DbgTrace("Reading IO port 0x%x (cap 0x%zx) failed with error %d\n",
		 Port->PortNum, Port->Cap, Reply.error);
	KeDbgDumpIPCError(Reply.error);
	return SEL4_ERROR(Reply.error);
    }
    *Out = Reply.result;
    return STATUS_SUCCESS;
}

static NTSTATUS IopWritePort8(IN PX86_IOPORT Port,
			      IN UCHAR Data)
{
    int Error = seL4_X86_IOPort_Out8(Port->Cap, Port->PortNum, Data);
    if (Error != 0) {
	DbgTrace("Writing IO port 0x%x (cap 0x%zx) with data 0x%x failed with error %d\n",
		 Port->PortNum, Port->Cap, Data, Error);
	KeDbgDumpIPCError(Error);
	return SEL4_ERROR(Error);
    }
    return STATUS_SUCCESS;
}

__cdecl UCHAR __inbyte(IN USHORT PortNum)
{
    PX86_IOPORT Port = IopFindIoPort(PortNum);
    if (Port == NULL) {
	NTSTATUS Status = IoEnableX86Port(PortNum);
	if (!NT_SUCCESS(Status)) {
	    RtlRaiseStatus(Status);
	}
	Port = IopFindIoPort(PortNum);
	if (Port == NULL) {
	    /* This is a bug. */
	    assert(FALSE);
	    RtlRaiseStatus(STATUS_UNSUCCESSFUL);
	}
    }
    UCHAR Value;
    NTSTATUS Status = IopReadPort8(Port, &Value);
    if (!NT_SUCCESS(Status)) {
	RtlRaiseStatus(STATUS_UNSUCCESSFUL);
    }
    return Value;
}

__cdecl VOID __outbyte(IN USHORT PortNum,
		       IN UCHAR Data)
{
    PX86_IOPORT Port = IopFindIoPort(PortNum);
    if (Port == NULL) {
	NTSTATUS Status = IoEnableX86Port(PortNum);
	if (!NT_SUCCESS(Status)) {
	    RtlRaiseStatus(Status);
	}
	Port = IopFindIoPort(PortNum);
	if (Port == NULL) {
	    /* This is a bug. */
	    assert(FALSE);
	    RtlRaiseStatus(STATUS_UNSUCCESSFUL);
	}
    }
    NTSTATUS Status = IopWritePort8(Port, Data);
    if (!NT_SUCCESS(Status)) {
	RtlRaiseStatus(STATUS_UNSUCCESSFUL);
    }
}
