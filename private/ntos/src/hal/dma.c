#include "halp.h"

/*
 * DMA Page  Register   Structure
 * 080       DMA        RESERVED
 * 081       DMA        Page Register (channel 2)
 * 082       DMA        Page Register (channel 3)
 * 083       DMA        Page Register (channel 1)
 * 084       DMA        RESERVED
 * 085       DMA        RESERVED
 * 086       DMA        RESERVED
 * 087       DMA        Page Register (channel 0)
 * 088       DMA        RESERVED
 * 089       PS/2-DMA   Page Register (channel 6)
 * 08A       PS/2-DMA   Page Register (channel 7)
 * 08B       PS/2-DMA   Page Register (channel 5)
 * 08C       PS/2-DMA   RESERVED
 * 08D       PS/2-DMA   RESERVED
 * 08E       PS/2-DMA   RESERVED
 * 08F       PS/2-DMA   Page Register (channel 4)
 */
typedef struct _DMA_PAGE {
    UCHAR Reserved1;
    UCHAR Channel2;
    UCHAR Channel3;
    UCHAR Channel1;
    UCHAR Reserved2[3];
    UCHAR Channel0;
    UCHAR Reserved3;
    UCHAR Channel6;
    UCHAR Channel7;
    UCHAR Channel5;
    UCHAR Reserved4[3];
    UCHAR Channel4;
} DMA_PAGE, *PDMA_PAGE;

/*
 * DMA Channel Mask Register Structure
 *
 * MSB                             LSB
 *       x   x   x   x     x   x   x   x
 *       -------------------   -   -----
 *                |            |     |     00 - Select channel 0 mask bit
 *                |            |     \---- 01 - Select channel 1 mask bit
 *                |            |           10 - Select channel 2 mask bit
 *                |            |           11 - Select channel 3 mask bit
 *                |            |
 *                |            \----------  0 - Clear mask bit
 *                |                         1 - Set mask bit
 *                |
 *                \----------------------- xx - Reserved
 */
typedef struct _DMA_CHANNEL_MASK {
    UCHAR Channel:2;
    UCHAR SetMask:1;
    UCHAR Reserved:5;
} DMA_CHANNEL_MASK, *PDMA_CHANNEL_MASK;

#define DMA_SETMASK	    4
#define DMA_CLEARMASK	    0
#define DMA_READ	    4
#define DMA_WRITE	    8
#define DMA_SINGLE_TRANSFER 0x40
#define DMA_AUTO_INIT	    0x10

typedef struct _DMA1_ADDRESS_COUNT {
    UCHAR DmaBaseAddress;
    UCHAR DmaBaseCount;
} DMA1_ADDRESS_COUNT, *PDMA1_ADDRESS_COUNT;

typedef struct _DMA2_ADDRESS_COUNT {
    UCHAR DmaBaseAddress;
    UCHAR Reserved1;
    UCHAR DmaBaseCount;
    UCHAR Reserved2;
} DMA2_ADDRESS_COUNT, *PDMA2_ADDRESS_COUNT;

typedef struct _DMA1_CONTROL {
    DMA1_ADDRESS_COUNT DmaAddressCount[4];
    UCHAR DmaStatus;
    UCHAR DmaRequest;
    UCHAR SingleMask;
    UCHAR Mode;
    UCHAR ClearBytePointer;
    UCHAR MasterClear;
    UCHAR ClearMask;
    UCHAR AllMask;
} DMA1_CONTROL, *PDMA1_CONTROL;

typedef struct _DMA2_CONTROL {
    DMA2_ADDRESS_COUNT DmaAddressCount[4];
    UCHAR DmaStatus;
    UCHAR Reserved1;
    UCHAR DmaRequest;
    UCHAR Reserved2;
    UCHAR SingleMask;
    UCHAR Reserved3;
    UCHAR Mode;
    UCHAR Reserved4;
    UCHAR ClearBytePointer;
    UCHAR Reserved5;
    UCHAR MasterClear;
    UCHAR Reserved6;
    UCHAR ClearMask;
    UCHAR Reserved7;
    UCHAR AllMask;
    UCHAR Reserved8;
} DMA2_CONTROL, *PDMA2_CONTROL;

/* Channel Stop Registers for each Channel */
typedef struct _DMA_CHANNEL_STOP {
    UCHAR ChannelLow;
    UCHAR ChannelMid;
    UCHAR ChannelHigh;
    UCHAR Reserved;
} DMA_CHANNEL_STOP, *PDMA_CHANNEL_STOP;

/* This structure defines the I/O Map of the 82537 controller.
 * We don't support EISA (only ISA is supported) so the extended
 * DMA fields are never used. */
typedef struct _EISA_CONTROL {
    /* DMA Controller 1 */
    DMA1_CONTROL DmaController1; /* 00h-0Fh */
    UCHAR Reserved1[16];	 /* 0Fh-1Fh */

    /* Interrupt Controller 1 (PIC) */
    UCHAR Pic1Operation;	/* 20h     */
    UCHAR Pic1Interrupt;	/* 21h     */
    UCHAR Reserved2[30];	/* 22h-3Fh */

    /* Timer */
    UCHAR TimerCounter;		/* 40h     */
    UCHAR TimerMemoryRefresh;	/* 41h     */
    UCHAR Speaker;		/* 42h     */
    UCHAR TimerOperation;	/* 43h     */
    UCHAR TimerMisc;		/* 44h     */
    UCHAR Reserved3[2];		/* 45-46h  */
    UCHAR TimerCounterControl;	/* 47h     */
    UCHAR TimerFailSafeCounter;	/* 48h     */
    UCHAR Reserved4;		/* 49h     */
    UCHAR TimerCounter2;	/* 4Ah     */
    UCHAR TimerOperation2;	/* 4Bh     */
    UCHAR Reserved5[20];	/* 4Ch-5Fh */

    /* NMI / Keyboard / RTC */
    UCHAR Keyboard;		/* 60h     */
    UCHAR NmiStatus;		/* 61h     */
    UCHAR Reserved6[14];	/* 62h-6Fh */
    UCHAR NmiEnable;		/* 70h     */
    UCHAR Reserved7[15];	/* 71h-7Fh */

    /* DMA Page Registers Controller 1 */
    DMA_PAGE DmaController1Pages; /* 80h-8Fh */
    UCHAR Reserved8[16];	  /* 90h-9Fh */

    /* Interrupt Controller 2 (PIC) */
    UCHAR Pic2Operation;	/* 0A0h      */
    UCHAR Pic2Interrupt;	/* 0A1h      */
    UCHAR Reserved9[30];	/* 0A2h-0BFh */

    /* DMA Controller 2 */
    DMA1_CONTROL DmaController2; /* 0C0h-0CFh */

    /* System Reserved Ports */
    UCHAR SystemReserved[816];	/* 0D0h-3FFh */

    /* Extended DMA Registers, Controller 1 */
    UCHAR DmaHighByteCount1[8];	/* 400h-407h */
    UCHAR Reserved10[2];	/* 408h-409h */
    UCHAR DmaChainMode1;	/* 40Ah      */
    UCHAR DmaExtendedMode1;	/* 40Bh      */
    UCHAR DmaBufferControl;	/* 40Ch      */
    UCHAR Reserved11[84];	/* 40Dh-460h */
    UCHAR ExtendedNmiControl;	/* 461h      */
    UCHAR NmiCommand;		/* 462h      */
    UCHAR Reserved12;		/* 463h      */
    UCHAR BusMaster;		/* 464h      */
    UCHAR Reserved13[27];	/* 465h-47Fh */

    /* DMA Page Registers Controller 2 */
    DMA_PAGE DmaController2Pages; /* 480h-48Fh */
    UCHAR Reserved14[48];	  /* 490h-4BFh */

    /* Extended DMA Registers, Controller 2 */
    UCHAR DmaHighByteCount2[16]; /* 4C0h-4CFh */

    /* Edge/Level Control Registers */
    UCHAR Pic1EdgeLevel;	/* 4D0h      */
    UCHAR Pic2EdgeLevel;	/* 4D1h      */
    UCHAR Reserved15[2];	/* 4D2h-4D3h */

    /* Extended DMA Registers, Controller 2 */
    UCHAR DmaChainMode2;	/* 4D4h      */
    UCHAR Reserved16;		/* 4D5h      */
    UCHAR DmaExtendedMode2;	/* 4D6h      */
    UCHAR Reserved17[9];	/* 4D7h-4DFh */

    /* DMA Stop Registers */
    DMA_CHANNEL_STOP DmaChannelStop[8];	/* 4E0h-4FFh */
} EISA_CONTROL, *PEISA_CONTROL;

static const ULONG_PTR HalpEisaPortPage[8] = {
    FIELD_OFFSET(DMA_PAGE, Channel0),
    FIELD_OFFSET(DMA_PAGE, Channel1),
    FIELD_OFFSET(DMA_PAGE, Channel2),
    FIELD_OFFSET(DMA_PAGE, Channel3),
    0,
    FIELD_OFFSET(DMA_PAGE, Channel5),
    FIELD_OFFSET(DMA_PAGE, Channel6),
    FIELD_OFFSET(DMA_PAGE, Channel7)
};

/*
 * System DMA Adapter object. This is the object that multiplexes
 * the (E)ISA DMA controller for client drivers. There is one singleton
 * object for each ISA DMA channel 0-7, except channel 4 which is
 * used for cascading and is therefore unavailable for device use.
 */
typedef struct _HAL_SYSYEM_ADAPTER {
    PVOID AdapterBaseVa;
    PUCHAR PagePort;
    UCHAR AdapterNumber;
    UCHAR ChannelNumber;
    USHORT DmaPortAddress;
} HAL_SYSTEM_ADAPTER, *PHAL_SYSTEM_ADAPTER;

static PHAL_SYSTEM_ADAPTER HalpEisaSystemAdapters[8];

static inline void *ULongToPtr(const unsigned long ul)
{
    return (void*)((ULONG_PTR)ul);
}

typedef struct _ADAPTER_OBJ_CREATE_CTX {
    UCHAR DmaChannel;
} ADAPTER_OBJ_CREATE_CTX, *PADAPTER_OBJ_CREATE_CTX;

#define ENABLE_PORT(p)	HalpEnableIoPort((USHORT)(ULONG_PTR)(p))

NTSTATUS HalpAdapterObjectCreateProc(IN POBJECT Object,
				     IN PVOID CreaCtx)
{
    PHAL_SYSTEM_ADAPTER AdapterObject = (PHAL_SYSTEM_ADAPTER)Object;
    PADAPTER_OBJ_CREATE_CTX Ctx = (PADAPTER_OBJ_CREATE_CTX)CreaCtx;
    PVOID BaseVa1 = ULongToPtr(FIELD_OFFSET(EISA_CONTROL, DmaController1));
    PVOID BaseVa2 = ULongToPtr(FIELD_OFFSET(EISA_CONTROL, DmaController2));
    UCHAR Controller = (Ctx->DmaChannel & 4) ? 2 : 1;
    AdapterObject->AdapterBaseVa = (Controller == 1) ? BaseVa1 : BaseVa2;
    AdapterObject->AdapterNumber = Controller;
    AdapterObject->ChannelNumber = (UCHAR)(Ctx->DmaChannel & 3);
    AdapterObject->PagePort = (PUCHAR)HalpEisaPortPage[Ctx->DmaChannel];
    UCHAR Channel = AdapterObject->ChannelNumber;
    if (Controller == 1) {
	PDMA1_CONTROL Ctrl = BaseVa1;
	RET_ERR(ENABLE_PORT(&Ctrl->ClearBytePointer));
	RET_ERR(ENABLE_PORT(&Ctrl->Mode));
	RET_ERR(ENABLE_PORT(&Ctrl->DmaAddressCount[Channel].DmaBaseAddress));
	RET_ERR(ENABLE_PORT(AdapterObject->PagePort +
			    FIELD_OFFSET(EISA_CONTROL, DmaController1Pages)));
	RET_ERR(ENABLE_PORT(&Ctrl->DmaAddressCount[Channel].DmaBaseCount));
	RET_ERR(ENABLE_PORT(&Ctrl->SingleMask));
    } else {
	assert(Controller == 2);
	PDMA2_CONTROL Ctrl = BaseVa2;
	RET_ERR(ENABLE_PORT(&Ctrl->ClearBytePointer));
	RET_ERR(ENABLE_PORT(&Ctrl->Mode));
	RET_ERR(ENABLE_PORT(&Ctrl->DmaAddressCount[Channel].DmaBaseAddress));
	RET_ERR(ENABLE_PORT(AdapterObject->PagePort +
			    FIELD_OFFSET(EISA_CONTROL, DmaController1Pages)));
	RET_ERR(ENABLE_PORT(&Ctrl->DmaAddressCount[Channel].DmaBaseCount));
	RET_ERR(ENABLE_PORT(&Ctrl->SingleMask));
    }
    return STATUS_SUCCESS;
}

NTSTATUS HalpInitDma()
{
    /* Create the system adapter object type */
    OBJECT_TYPE_INITIALIZER TypeInfo = {
	.CreateProc = HalpAdapterObjectCreateProc,
	.ParseProc = NULL,
	.OpenProc = NULL,
	.InsertProc = NULL,
	.RemoveProc = NULL,
	.DeleteProc = NULL
    };
    RET_ERR(ObCreateObjectType(OBJECT_TYPE_SYSTEM_ADAPTER, "Adapter",
			       sizeof(HAL_SYSTEM_ADAPTER), TypeInfo));

    /* Create the system adapter objects. There is one for each ISA DMA
     * channel, except channel 4. */
    ADAPTER_OBJ_CREATE_CTX Ctx;
    for (int i = 0; i < ARRAYSIZE(HalpEisaSystemAdapters); i++) {
	if (i == 4) {
	    continue;
	}
	Ctx.DmaChannel = i;
	RET_ERR(ObCreateObject(OBJECT_TYPE_SYSTEM_ADAPTER,
			       (POBJECT *)&HalpEisaSystemAdapters[i], &Ctx));
	assert(HalpEisaSystemAdapters[i] != NULL);
    }

    return STATUS_SUCCESS;
}

NTSTATUS HalpDmaOpenSystemAdapter(IN ASYNC_STATE AsyncState,
				  IN PTHREAD Thread,
				  IN UCHAR DmaChannel,
				  OUT HANDLE *Handle)
{
    if (DmaChannel >= 8) {
	return STATUS_INVALID_PARAMETER;
    }
    PHAL_SYSTEM_ADAPTER AdapterObject = HalpEisaSystemAdapters[DmaChannel];
    if (AdapterObject == NULL) {
	return STATUS_NO_SUCH_DEVICE;
    }
    return ObCreateHandle(Thread->Process, AdapterObject, Handle);
}

NTSTATUS HalpDmaStartTransfer(IN ASYNC_STATE AsyncState,
			      IN PTHREAD Thread,
			      IN HANDLE AdapterHandle,
			      IN UCHAR DmaMode,
			      IN USHORT TransferOffset,
			      IN USHORT TransferLength,
			      IN UCHAR HighByte)
{
    if (TransferLength == 0) {
	return STATUS_INVALID_PARAMETER_4;
    }

    PHAL_SYSTEM_ADAPTER AdapterObject = NULL;
    RET_ERR(ObReferenceObjectByHandle(Thread->Process, AdapterHandle,
				      OBJECT_TYPE_SYSTEM_ADAPTER,
				      (POBJECT *)&AdapterObject));
    assert(AdapterObject != NULL);

    UCHAR Channel = AdapterObject->ChannelNumber;
    if (AdapterObject->AdapterNumber == 1) {
	PDMA1_CONTROL DmaControl1 = AdapterObject->AdapterBaseVa;

	/* Reset Register */
	WRITE_PORT_UCHAR(&DmaControl1->ClearBytePointer, 0);

	/* Set the Mode */
	WRITE_PORT_UCHAR(&DmaControl1->Mode, DmaMode);

	/* Set the Offset Register */
	WRITE_PORT_UCHAR(&DmaControl1->DmaAddressCount[Channel].DmaBaseAddress,
			 (UCHAR)TransferOffset);
	WRITE_PORT_UCHAR(&DmaControl1->DmaAddressCount[Channel].DmaBaseAddress,
			 (UCHAR)(TransferOffset >> 8));

	/* Set the Page Register */
	WRITE_PORT_UCHAR(AdapterObject->PagePort + FIELD_OFFSET(EISA_CONTROL,
								DmaController1Pages),
			 HighByte);

	/* Set the Length */
	WRITE_PORT_UCHAR(&DmaControl1->DmaAddressCount[Channel].DmaBaseCount,
			 (UCHAR)(TransferLength - 1));
	WRITE_PORT_UCHAR(&DmaControl1->DmaAddressCount[Channel].DmaBaseCount,
			 (UCHAR)((TransferLength - 1) >> 8));

	/* Unmask the Channel */
	WRITE_PORT_UCHAR(&DmaControl1->SingleMask, Channel | DMA_CLEARMASK);
    } else {
	PDMA2_CONTROL DmaControl2 = AdapterObject->AdapterBaseVa;

	/* Reset Register */
	WRITE_PORT_UCHAR(&DmaControl2->ClearBytePointer, 0);

	/* Set the Mode */
	WRITE_PORT_UCHAR(&DmaControl2->Mode, DmaMode);

	/* Set the Offset Register */
	WRITE_PORT_UCHAR(&DmaControl2->DmaAddressCount[Channel].DmaBaseAddress,
			 (UCHAR)(TransferOffset));
	WRITE_PORT_UCHAR(&DmaControl2->DmaAddressCount[Channel].DmaBaseAddress,
			 (UCHAR)(TransferOffset >> 8));

	/* Set the Page Register */
	WRITE_PORT_UCHAR(AdapterObject->PagePort + FIELD_OFFSET(EISA_CONTROL,
								DmaController1Pages),
			 HighByte);

	/* Set the Length */
	WRITE_PORT_UCHAR(&DmaControl2->DmaAddressCount[Channel].DmaBaseCount,
			 (UCHAR)(TransferLength - 1));
	WRITE_PORT_UCHAR(&DmaControl2->DmaAddressCount[Channel].DmaBaseCount,
			 (UCHAR)((TransferLength - 1) >> 8));

	/* Unmask the Channel */
	WRITE_PORT_UCHAR(&DmaControl2->SingleMask, Channel | DMA_CLEARMASK);
    }

    ObDereferenceObject(AdapterObject);
    return STATUS_SUCCESS;
}

NTSTATUS HalpDmaDisableChannel(IN ASYNC_STATE AsyncState,
			       IN PTHREAD Thread,
			       IN HANDLE AdapterHandle)
{
    PHAL_SYSTEM_ADAPTER AdapterObject = NULL;
    RET_ERR(ObReferenceObjectByHandle(Thread->Process, AdapterHandle,
				      OBJECT_TYPE_SYSTEM_ADAPTER,
				      (POBJECT *)&AdapterObject));
    assert(AdapterObject != NULL);

    /* Mask the DMA channel */
    UCHAR Channel = AdapterObject->ChannelNumber;
    if (AdapterObject->AdapterNumber == 1) {
	PDMA1_CONTROL DmaControl1 = AdapterObject->AdapterBaseVa;
	WRITE_PORT_UCHAR(&DmaControl1->SingleMask, Channel | DMA_SETMASK);
    } else {
	PDMA2_CONTROL DmaControl2 = AdapterObject->AdapterBaseVa;
	WRITE_PORT_UCHAR(&DmaControl2->SingleMask, Channel | DMA_SETMASK);
    }

    ObDereferenceObject(AdapterObject);
    return STATUS_SUCCESS;
}

NTSTATUS HalpDmaReadProgressCounter(IN ASYNC_STATE AsyncState,
				    IN PTHREAD Thread,
				    IN HANDLE AdapterHandle,
				    OUT ULONG *pCount)
{
    PHAL_SYSTEM_ADAPTER AdapterObject = NULL;
    RET_ERR(ObReferenceObjectByHandle(Thread->Process, AdapterHandle,
				      OBJECT_TYPE_SYSTEM_ADAPTER,
				      (POBJECT *)&AdapterObject));
    assert(AdapterObject != NULL);

    /* Send the request to the specific controller. */
    UCHAR Channel = AdapterObject->ChannelNumber;
    ULONG Count = 0xffff00;
    if (AdapterObject->AdapterNumber == 1) {
	PDMA1_CONTROL Ctrl = AdapterObject->AdapterBaseVa;

	ULONG OldCount;
	do {
	    OldCount = Count;

	    /* Send Reset */
	    WRITE_PORT_UCHAR(&Ctrl->ClearBytePointer, 0);

	    /* Read Count */
	    Count = READ_PORT_UCHAR(&Ctrl->DmaAddressCount[Channel].DmaBaseCount);
	    Count |= READ_PORT_UCHAR(&Ctrl->DmaAddressCount[Channel].DmaBaseCount) << 8;
	} while (0xffff00 & (OldCount ^ Count));
    } else {
	PDMA2_CONTROL Ctrl = AdapterObject->AdapterBaseVa;

	ULONG OldCount;
	do {
	    OldCount = Count;

	    /* Send Reset */
	    WRITE_PORT_UCHAR(&Ctrl->ClearBytePointer, 0);

	    /* Read Count */
	    Count = READ_PORT_UCHAR(&Ctrl->DmaAddressCount[Channel].DmaBaseCount);
	    Count |= READ_PORT_UCHAR(&Ctrl->DmaAddressCount[Channel].DmaBaseCount) << 8;
	} while (0xffff00 & (OldCount ^ Count));
    }

    *pCount = Count;
    ObDereferenceObject(AdapterObject);
    return STATUS_SUCCESS;
}

NTSTATUS HalpAllocateDmaBuffer(IN ASYNC_STATE AsyncState,
                               IN PTHREAD Thread,
                               IN ULONG Length,
                               IN PPHYSICAL_ADDRESS HighestAddr,
                               IN ULONG BoundaryAddressBits,
                               OUT PVOID *pVirtAddr,
                               OUT PHYSICAL_ADDRESS *pPhyAddr)
{
    /* Length cannot be larger than the contiguous bank that the
     * DMA controller/device can access. For instance, if the
     * DMA adapter is the ISA DMA controller, than Length must
     * be less than 64KB (BoundaryAddressBits == 16). */
    if (Length > (1ULL << BoundaryAddressBits)) {
	return STATUS_INVALID_PARAMETER;
    }
    MWORD VirtAddr = 0;
    MWORD PhyAddr = 0;
    RET_ERR(MmAllocatePhysicallyContiguousMemory(&Thread->Process->VSpace,
						 Length,
						 HighestAddr->QuadPart,
						 &VirtAddr, &PhyAddr));
    *pVirtAddr = (PVOID)VirtAddr;
    pPhyAddr->QuadPart = PhyAddr;
    return STATUS_SUCCESS;
}
