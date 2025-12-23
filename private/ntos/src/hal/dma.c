#include "halp.h"

#if defined(_M_IX86) || defined(_M_AMD64)

/*
 * R/W Page Address Register for each ISA DMA channel
 *
 * The first column of this table is the IO port number
 * of each page address register.
 *
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
 * DMA Channel Mask Registers (0x0A and 0xD4, Write) Structure
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

/*
 * DMA controller registers. Each 8237A has 18 registers, addressed via
 * the I/O Port bus. The starting IO port number for the DMA1 controller
 * is 0x00.
 */
typedef struct _DMA1_CONTROL {
    DMA1_ADDRESS_COUNT DmaAddressCount[4];
    UCHAR DmaStatus;		/* 0x08 */
    UCHAR DmaRequest;		/* 0x09 */
    UCHAR SingleMask;		/* 0x0A */
    UCHAR Mode;			/* 0x0B */
    UCHAR ClearBytePointer;	/* 0x0C */
    UCHAR MasterClear;		/* 0x0D */
    UCHAR ClearMask;		/* 0x0E */
    UCHAR AllMask;		/* 0x0F */
} DMA1_CONTROL, *PDMA1_CONTROL;

/*
 * The starting IO port number for the DMA2 controller is 0xC0.
 */
typedef struct _DMA2_CONTROL {
    DMA2_ADDRESS_COUNT DmaAddressCount[4];
    UCHAR DmaStatus;		/* 0xD0 */
    UCHAR Reserved1;
    UCHAR DmaRequest;		/* 0xD2 */
    UCHAR Reserved2;
    UCHAR SingleMask;		/* 0xD4 */
    UCHAR Reserved3;
    UCHAR Mode;			/* 0xD6 */
    UCHAR Reserved4;
    UCHAR ClearBytePointer;	/* 0xD8 */
    UCHAR Reserved5;
    UCHAR MasterClear;		/* 0xDA */
    UCHAR Reserved6;
    UCHAR ClearMask;		/* 0xDC */
    UCHAR Reserved7;
    UCHAR AllMask;		/* 0xDE */
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
    UCHAR Reserved1[16];	 /* 10h-1Fh */

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
    DMA2_CONTROL DmaController2; /* 0C0h-0DFh */

    /* System Reserved Ports */
    UCHAR SystemReserved[0x320]; /* 0E0h-3FFh */

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

C_ASSERT(FIELD_OFFSET(EISA_CONTROL, DmaController2) == 0xC0);
C_ASSERT(FIELD_OFFSET(EISA_CONTROL, SystemReserved) == 0xE0);
C_ASSERT(FIELD_OFFSET(EISA_CONTROL, DmaHighByteCount1) == 0x400);

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

typedef struct _ADAPTER_OBJ_CREATE_CTX {
    UCHAR DmaChannel;
} ADAPTER_OBJ_CREATE_CTX, *PADAPTER_OBJ_CREATE_CTX;

#define ENABLE_PORT(p)		HalpEnableIoPort((USHORT)(ULONG_PTR)(p), 1)
#define DMA_INIT_CONTROLLER(Ctrl)					\
    RET_ERR(ENABLE_PORT(&Ctrl->ClearBytePointer));			\
    RET_ERR(ENABLE_PORT(&Ctrl->Mode));					\
    RET_ERR(ENABLE_PORT(&Ctrl->DmaAddressCount[Channel].DmaBaseAddress)); \
    RET_ERR(ENABLE_PORT(AdapterObject->PagePort +			\
			FIELD_OFFSET(EISA_CONTROL, DmaController1Pages))); \
    RET_ERR(ENABLE_PORT(&Ctrl->DmaAddressCount[Channel].DmaBaseCount));	\
    RET_ERR(ENABLE_PORT(&Ctrl->SingleMask))

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
	DMA_INIT_CONTROLLER(Ctrl);
    } else {
	assert(Controller == 2);
	PDMA2_CONTROL Ctrl = BaseVa2;
	DMA_INIT_CONTROLLER(Ctrl);
    }
    return STATUS_SUCCESS;
}

static SMBIOS_MATCH_ENTRY_TABLE HalpIsaDmaQuirkMatchTable[] = {
    {	 /* GPD MicroPC (generic strings, also match on bios date)  */
	{ SYS_VENDOR, "Default string" },
	{ SYS_PRODUCT, "Default string" },
	{ BOARD_VENDOR, "Default string" },
	{ BOARD_NAME, "Default string" }
    },
    {  /* GPD MicroPC (later BIOS versions with proper DMI strings) */
	{ SYS_VENDOR, "GPD" },
	{ SYS_PRODUCT, "MicroPC" }
    }
};

/* Returns TRUE if the platform does not support ISA DMA. */
static BOOLEAN HalpSkipIsaDmaInit()
{
    for (ULONG i = 0; i < _ARRAYSIZE(HalpIsaDmaQuirkMatchTable); i++) {
	ULONG j;
	for (j = 0; j < MAX_MATCH_ENTRIES; j++) {
	    ULONG Type = HalpIsaDmaQuirkMatchTable[i][j].Type;

	    if (Type == SMBIOS_STRING_ID_NONE) {
		/* Note this does NOT skip the increment (j++). */
		continue;
	    }

	    /* If the specified string does not match, break out of the loop.
	     * Note in this case j will be strictly less than MAX_MATCH_ENTRIES. */
	    if (!HalpSmbiosStrings[Type] ||
		strcmp(HalpIsaDmaQuirkMatchTable[i][j].String,
		       HalpSmbiosStrings[Type])) {
		break;
	    }
	}

	if (j == MAX_MATCH_ENTRIES) {
	    return TRUE;
	}
    }

    return FALSE;
}

NTSTATUS HalpInitDma()
{
    /* On platforms that do not support ISA DMA, we skip ISA DMA init. */
    if (HalpSkipIsaDmaInit()) {
	return STATUS_SUCCESS;
    }

    /* Create the system adapter object type */
    OBJECT_TYPE_INITIALIZER TypeInfo = {
	.CreateProc = HalpAdapterObjectCreateProc,
	.ParseProc = NULL,
	.OpenProc = NULL,
	.CloseProc = NULL,
	.InsertProc = NULL,
	.RemoveProc = NULL,
	.QueryNameProc = NULL,
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

NTSTATUS WdmHalDmaOpenSystemAdapter(IN ASYNC_STATE AsyncState,
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
    return ObCreateHandle(Thread->Process, AdapterObject, FALSE, Handle, NULL);
}

#define DMA_START_TRANSFER(Ty)						\
    Ty *Ctrl = AdapterObject->AdapterBaseVa;				\
									\
    /* Reset Register */						\
    WRITE_PORT_UCHAR(&Ctrl->ClearBytePointer, 0);			\
									\
    /* Set the Mode */							\
    WRITE_PORT_UCHAR(&Ctrl->Mode, DmaMode);				\
									\
    /* Set the Offset Register */					\
    WRITE_PORT_UCHAR(&Ctrl->DmaAddressCount[Channel].DmaBaseAddress,	\
		     (UCHAR)(TransferOffset));				\
    WRITE_PORT_UCHAR(&Ctrl->DmaAddressCount[Channel].DmaBaseAddress,	\
		     (UCHAR)(TransferOffset >> 8));			\
									\
    /* Set the Page Register */						\
    WRITE_PORT_UCHAR(AdapterObject->PagePort +				\
		     FIELD_OFFSET(EISA_CONTROL, DmaController1Pages),	\
		     HighByte);						\
									\
    /* Set the Length */						\
    WRITE_PORT_UCHAR(&Ctrl->DmaAddressCount[Channel].DmaBaseCount,	\
		     (UCHAR)(TransferLength - 1));			\
    WRITE_PORT_UCHAR(&Ctrl->DmaAddressCount[Channel].DmaBaseCount,	\
		     (UCHAR)((TransferLength - 1) >> 8));		\
									\
    /* Unmask the Channel */						\
    WRITE_PORT_UCHAR(&Ctrl->SingleMask, Channel | DMA_CLEARMASK)


NTSTATUS WdmHalDmaStartTransfer(IN ASYNC_STATE AsyncState,
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
    RET_ERR(ObReferenceObjectByHandle(Thread, AdapterHandle,
				      OBJECT_TYPE_SYSTEM_ADAPTER,
				      (POBJECT *)&AdapterObject));
    assert(AdapterObject != NULL);

    UCHAR Channel = AdapterObject->ChannelNumber;
    if (AdapterObject->AdapterNumber == 1) {
	DMA_START_TRANSFER(DMA1_CONTROL);
    } else {
	DMA_START_TRANSFER(DMA2_CONTROL);
    }

    ObDereferenceObject(AdapterObject);
    return STATUS_SUCCESS;
}

NTSTATUS WdmHalDmaDisableChannel(IN ASYNC_STATE AsyncState,
				 IN PTHREAD Thread,
				 IN HANDLE AdapterHandle)
{
    PHAL_SYSTEM_ADAPTER AdapterObject = NULL;
    RET_ERR(ObReferenceObjectByHandle(Thread, AdapterHandle,
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

NTSTATUS WdmHalDmaReadProgressCounter(IN ASYNC_STATE AsyncState,
				      IN PTHREAD Thread,
				      IN HANDLE AdapterHandle,
				      OUT ULONG *pCount)
{
    PHAL_SYSTEM_ADAPTER AdapterObject = NULL;
    RET_ERR(ObReferenceObjectByHandle(Thread, AdapterHandle,
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

#else

NTSTATUS HalpInitDma()
{
    return STATUS_SUCCESS;
}

NTSTATUS WdmHalDmaOpenSystemAdapter(IN ASYNC_STATE AsyncState,
				    IN PTHREAD Thread,
				    IN UCHAR DmaChannel,
				    OUT HANDLE *Handle)
{
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS WdmHalDmaStartTransfer(IN ASYNC_STATE AsyncState,
				IN PTHREAD Thread,
				IN HANDLE AdapterHandle,
				IN UCHAR DmaMode,
				IN USHORT TransferOffset,
				IN USHORT TransferLength,
				IN UCHAR HighByte)
{
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS WdmHalDmaDisableChannel(IN ASYNC_STATE AsyncState,
				 IN PTHREAD Thread,
				 IN HANDLE AdapterHandle)
{
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS WdmHalDmaReadProgressCounter(IN ASYNC_STATE AsyncState,
				      IN PTHREAD Thread,
				      IN HANDLE AdapterHandle,
				      OUT ULONG *pCount)
{
    return STATUS_NOT_SUPPORTED;
}
#endif

NTSTATUS WdmHalAllocateDmaBuffer(IN ASYNC_STATE AsyncState,
				 IN PTHREAD Thread,
				 IN MWORD Length,
				 IN PPHYSICAL_ADDRESS HighestAddr,
				 IN ULONG BoundaryAddressBits,
				 IN MEMORY_CACHING_TYPE CacheType,
				 OUT PVOID *pVirtAddr,
				 OUT PHYSICAL_ADDRESS *pPhyAddr)
{
    Length = PAGE_ALIGN_UP(Length);
    /* Length cannot be larger than the contiguous bank that the
     * DMA controller/device can access. For instance, if the
     * DMA adapter is the ISA DMA controller, than Length must
     * be less than 64KB (BoundaryAddressBits == 16). */
    if (BoundaryAddressBits && (Length > (1ULL << BoundaryAddressBits))) {
	return STATUS_INVALID_PARAMETER;
    }
    MWORD VirtAddr = 0;
    MWORD PhyAddr = 0;
    RET_ERR(MmAllocatePhysicallyContiguousMemory(&Thread->Process->VSpace,
						 Length,
						 HighestAddr->QuadPart,
						 CacheType,
						 &VirtAddr, &PhyAddr));
    *pVirtAddr = (PVOID)VirtAddr;
    pPhyAddr->QuadPart = PhyAddr;
    return STATUS_SUCCESS;
}

NTSTATUS WdmHalFreeDmaBuffer(IN ASYNC_STATE AsyncState,
			     IN PTHREAD Thread,
			     IN PVOID BaseAddress,
			     IN SIZE_T NumberOfBytes,
			     IN MEMORY_CACHING_TYPE CacheType)
{
    return MmFreePhysicallyContiguousMemory(&Thread->Process->VSpace,
					    (MWORD)BaseAddress,
					    NumberOfBytes, CacheType);
}
