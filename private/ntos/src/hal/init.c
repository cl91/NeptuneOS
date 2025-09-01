#include "halp.h"

#if defined(_M_IX86) || defined(_M_AMD64)

static LIST_ENTRY HalpX86IoPortList;

NTSTATUS HalpEnableIoPort(USHORT PortNum, USHORT Count)
{
    PLIST_ENTRY InsertAfter = &HalpX86IoPortList;
    /* Traverse the port list and find where we should insert the node */
    LoopOverList(Entry, &HalpX86IoPortList, X86_IOPORT, Link) {
	if (Entry->PortNum == PortNum) {
	    return STATUS_SUCCESS;
	} else if (Entry->PortNum < PortNum) {
	    InsertAfter = &Entry->Link;
	} else {
	    assert(Entry->PortNum > PortNum);
	    break;
	}
    }
    HalpAllocatePool(IoPort, X86_IOPORT);
    RET_ERR_EX(KeEnableIoPort(PortNum, Count, IoPort),
	       HalpFreePool(IoPort));
    InsertHeadList(InsertAfter, &IoPort->Link);
    return STATUS_SUCCESS;
}

static inline PX86_IOPORT HalpFindIoPort(USHORT PortNum)
{
    LoopOverList(Entry, &HalpX86IoPortList, X86_IOPORT, Link) {
	if (Entry->PortNum == PortNum) {
	    return Entry;
	}
    }
    return NULL;
}

UCHAR __inbyte(IN USHORT PortNum)
{
    PX86_IOPORT Port = HalpFindIoPort(PortNum);
    if (Port == NULL) {
	KeBugCheckMsg("Port number 0x%x not initialized.\n", PortNum);
    }
    UCHAR Value;
    NTSTATUS Status = KeReadPort8(Port, &Value);
    if (!NT_SUCCESS(Status)) {
	KeBugCheckMsg("Unable to read from port 0x%x.\n", PortNum);
    }
    return Value;
}

VOID __outbyte(IN USHORT PortNum,
	       IN UCHAR Data)
{
    PX86_IOPORT Port = HalpFindIoPort(PortNum);
    if (Port == NULL) {
	KeBugCheckMsg("Port number 0x%x not initialized.\n", PortNum);
    }
    NTSTATUS Status = KeWritePort8(Port, Data);
    if (!NT_SUCCESS(Status)) {
	KeBugCheckMsg("Unable to write data 0x%02x to port 0x%x.\n",
		      Data, PortNum);
    }
}

#endif	/* defined(_M_IX86) || defined(_M_AMD64) */

NTSTATUS HalInitSystemPhase0(VOID)
{
#if defined(_M_IX86) || defined(_M_AMD64)
    InitializeListHead(&HalpX86IoPortList);
#endif
    RET_ERR(HalpInitVga());
    RET_ERR(HalpInitCmos());
    return STATUS_SUCCESS;
}

NTSTATUS HalInitSystemPhase1(VOID)
{
    RET_ERR(HalpInitBeep());
    RET_ERR(HalpInitDma());
    return STATUS_SUCCESS;
}

NTSTATUS HalMaskUnusableInterrupts(VOID)
{
    /* Mask timer IRQL and IRQL 2 (which is unusable on PIC systems). */
    IoMaskInterrupt(TIMER_IRQ_LINE);
    IoMaskInterrupt(2);
}
