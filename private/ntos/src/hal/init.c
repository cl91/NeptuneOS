#include "halp.h"

static LIST_ENTRY HalpX86IoPortList;

NTSTATUS HalpEnableIoPort(USHORT PortNum)
{
    PLIST_ENTRY InsertAfter = &HalpX86IoPortList;
    /* Traverse the port list and find where we should insert the node */
    LoopOverList(Entry, &HalpX86IoPortList, HAL_IOPORT, Link) {
	if (Entry->IoPort.PortNum == PortNum) {
	    return STATUS_SUCCESS;
	} else if (Entry->IoPort.PortNum < PortNum) {
	    InsertAfter = &Entry->Link;
	} else {
	    assert(Entry->IoPort.PortNum > PortNum);
	    break;
	}
    }
    HalpAllocatePool(IoPort, HAL_IOPORT);
    RET_ERR_EX(KeEnableIoPort(PortNum, &IoPort->IoPort),
	       ExFreePool(IoPort));
    InsertHeadList(InsertAfter, &IoPort->Link);
    return STATUS_SUCCESS;
}

static inline PHAL_IOPORT HalpFindIoPort(USHORT PortNum)
{
    LoopOverList(Entry, &HalpX86IoPortList, HAL_IOPORT, Link) {
	if (Entry->IoPort.PortNum == PortNum) {
	    return Entry;
	}
    }
    return NULL;
}

UCHAR __inbyte(IN USHORT PortNum)
{
    PHAL_IOPORT Port = HalpFindIoPort(PortNum);
    if (Port == NULL) {
	KeBugCheckMsg("Port number 0x%x not initialized.\n", PortNum);
    }
    UCHAR Value;
    NTSTATUS Status = KeReadPort8(&Port->IoPort, &Value);
    if (!NT_SUCCESS(Status)) {
	KeBugCheckMsg("Unable to read from port 0x%x.\n", PortNum);
    }
    return Value;
}

VOID __outbyte(IN USHORT PortNum,
	       IN UCHAR Data)
{
    PHAL_IOPORT Port = HalpFindIoPort(PortNum);
    if (Port == NULL) {
	KeBugCheckMsg("Port number 0x%x not initialized.\n", PortNum);
    }
    NTSTATUS Status = KeWritePort8(&Port->IoPort, Data);
    if (!NT_SUCCESS(Status)) {
	KeBugCheckMsg("Unable to write data 0x%02x to port 0x%x.\n",
		      Data, PortNum);
    }
}

NTSTATUS HalInitSystemPhase0(VOID)
{
    InitializeListHead(&HalpX86IoPortList);
    RET_ERR(HalpInitVga());
    RET_ERR(HalpInitCmos());
    return STATUS_SUCCESS;
}

NTSTATUS HalInitSystemPhase1(VOID)
{
    RET_ERR(HalpInitBeep());
    return STATUS_SUCCESS;
}
