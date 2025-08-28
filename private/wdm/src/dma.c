/*
 *
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS kernel
 * FILE:            hal/halx86/generic/dma.c
 * PURPOSE:         DMA functions
 * PROGRAMMERS:     David Welch (welch@mcmail.com)
 *                  Filip Navara (navaraf@reactos.com)
 * UPDATE HISTORY:
 *                  Created 22/05/98
 */

/**
 * @page DMA Implementation Notes
 *
 * These are adapted from the notes in the original ReactOS implementation of
 * the x86 DMA (as part of the x86 HAL). We made several important modifications
 * to the ReactOS DMA implementation. These are discussed in details below.
 *
 * Concepts:
 *
 * - Bus-master / Slave DMA
 *
 *   Slave DMA is a term used for DMA transfers done by the system (E)ISA
 *   controller as opposed to transfers mastered by the device itself
 *   (hence the name). Slave DMA is a relic of the old ISA bus. For modern
 *   PCI/PCI-Express buses there is no dedicated DMA controller, and all
 *   PCI(E) devices can access the physical memory either directly or via
 *   an IOMMU. This mode of DMA is called bus-mastering DMA because in this
 *   case the devices become the master of the bus data transfer.
 *
 *   For devices that support bus mastering DMA with scatter gather, very
 *   little is needed on the software side. We simply find out the physical
 *   addresses of the IO buffers and pass them to the devices. This in general
 *   has higher performance and is therefore the preferred, modern approach
 *   to DMA transfers. (For bus master devices without scatter gather, we
 *   allocate a common buffer to encompass the MDL. See below for details.)
 *
 *   For slave DMA, special care is taken to actually access the system
 *   controller and handle the transfers. The relevant code is in
 *   HalpDmaGetSystemAdapter, HalpReadDmaCounter, HalpFlushAdapterBuffers
 *   and HalpMapTransfer.
 *
 * - Map register
 *
 *   Abstract encapsulation of physically contiguous buffer that resides
 *   in memory accessible by both the DMA device/controller and the system.
 *   The map registers are allocated and distributed on demand and are
 *   scarce resource.
 *
 *   The actual use of map registers is to allow transfers from/to buffer
 *   located in physical memory at address inaccessible by the DMA device/
 *   controller directly. For such transfers the map register buffers are
 *   used as intermediate "bounce buffers". This technique is called 'double
 *   buffering'. There are three common cases: 1) for the ISA bus, its DMA
 *   controller can only access the lowest 16MB (24-bit) physical address
 *   space, and 2) on 64bit systems, some 32-bit PCI devices can only access
 *   the lowest 4GB physical address space, and finally 3) if the driver
 *   indicates that the device does not support scatter/gather, we need to
 *   allocate an intermediate buffer that encompasses the entire data buffer
 *   described by the MDL.
 *
 * - Map register control (Windows uses the term 'master adapter')
 *
 *   A container for map registers (typically corresponding to one physical
 *   bus connection type). Windows uses the term 'master adapter' for these.
 *   We feel that this is somewhat confusing as this is an orthogonal concept
 *   to 'bus mastering DMA' (in fact, most bus mastering DMA transfers do
 *   not need map registers). This is a singleton object for the entire driver
 *   process. When the driver tries to allocate a common buffer, it will be
 *   done through the map register control object that takes care of freeing
 *   them later.
 *
 * Implementation:
 *
 * - Allocation of map registers
 *
 *   We allocate the map registers by requesting the server. When the client
 *   tries to allocate map registers, HalpAllocateAdapterChannel first checks if
 *   there are free map registers on the client side and use them if there are.
 *   If not, it calls server to allocate more map registers. When the client frees
 *   the map registers, instead of returning them back to the server right away,
 *   HalpFreeAdapterChannel marks them as freed so future allocations do not
 *   have to make a trip to the server. Only when the server notifies the client
 *   that it is running low on map registers will we actually return the map
 *   registers back to the server.
 *
 *   Allocations are done synchronously. There is no need for work items as
 *   opposed to the ReactOS implementation (work items won't work for this
 *   purpose because work items are executed in the main thread). This vastly
 *   simplifies the implementation.
 *
 *   The server always allocates memory from high addresses first. In other words
 *   the server always allocates memory above 4GB if it's available, and failing
 *   that will attempt to allocate memory between 16MB and 4GB. Only when all
 *   memories above 16MB are exhausted will the server attempt to allocate memory
 *   below the 16MB limit. This ensures that on system with sufficient RAM we
 *   always will be able to allocate map registers.
 *
 *   Note that even if no more map registers can be allocated at the moment it's
 *   not the end of the world. The adapters waiting for free map registers are
 *   queuedin the server's queue and once one driver hands back its map registers
 *   (by responding to the server message to release unused map registers) the
 *   queue gets processed and the map registers are reassigned.
 *
 * - EISA Support
 *
 *   Since Neptune OS requires at least a Pentium II, we have removed the
 *   support for the EISA bus in the original ReactOS DMA implementation.
 *   The older ISA bus is still supported because it is used by the floppy
 *   controller and some sound cards such as the Sound Blaster. However its
 *   function is limited to the first 8 DMA channel with slave DMA mode. No
 *   ISA bus mastering devices are supported.
 *
 * - IgnoreCount
 *   Some (E)ISA DMA controllers cannot accurately maintain the DMA progress
 *   counters. Microsoft therefore added the IgnoreCount member of the device
 *   description structure which the driver author can specify so the system
 *   will ignore what the DMA progress counter reports and maintain the counter
 *   manually. Since reading the DMA progress counter requires a trip to the
 *   server, we have deciced to always ignore the DMA controller's progress
 *   counter.
 */

/* INCLUDES *****************************************************************/

#include <wdmp.h>
#include "haldma.h"

/* List of all DMA adapter objects of this driver */
static LIST_ENTRY HalpDmaAdapterList;

/* Map register control object */
static MAP_REGISTER_CONTROL HalpDmaMapRegCtrl;

/* System adapter objects. These are uninitialized after driver startup and
 * are initialized on-demand. */
static SYSTEM_DMA_ADAPTER HalpDmaSystemAdapters[8];

/* Forward declaration. See end of file for definition. */
static DMA_OPERATIONS HalpDmaOperations;
NTAPI VOID HalpFreeAdapterChannel(IN PDMA_ADAPTER DmaAdapter);

#define MAX_SG_ELEMENTS	    0x10

#define TAG_DMA ' AMD'

/* FUNCTIONS *****************************************************************/

/**
 * @name HalpInitMapRegControl
 *
 * Helper routine to initialize the map register control object. The initial
 * map register control object has no map registers allocated.
 *
 * @see HalpInitDma
 */
static VOID HalpInitMapRegCtrl(IN PMAP_REGISTER_CONTROL MapRegCtrl)
{
    InitializeListHead(&MapRegCtrl->List);
}

/**
 * @name HalpInitDma
 *
 * Intialize all the global variables and the map register control objects.
 * This is called during driver initialization.
 *
 * @see WdmStartup
 */
VOID HalpInitDma()
{
    InitializeListHead(&HalpDmaAdapterList);
    HalpInitMapRegCtrl(&HalpDmaMapRegCtrl);
}

/**
 * @name HalpDmaGetSystemAdapter
 *
 * Setup DMA modes and extended modes for (E)ISA DMA adapter object.
 */
static PSYSTEM_DMA_ADAPTER HalpDmaGetSystemAdapter(IN PDEVICE_DESCRIPTION Desc)
{
    assert(Desc->DmaChannel < 8);
    assert(Desc->DmaChannel != 4);
    assert(!Desc->Master);

    UCHAR Controller = (Desc->DmaChannel & 4) ? 2 : 1;

    /*
     * Validate setup for non-busmaster DMA adapter. Secondary controller
     * supports only 16-bit transfers and main controller supports only
     * 8-bit transfers. Anything else is invalid.
     */
    if (Controller == 1 && Desc->DmaWidth != Width8Bits) {
	DPRINT("Invalid width for system DMA controller\n");
	return NULL;
    } else if (Controller == 2 && Desc->DmaWidth != Width16Bits) {
	DPRINT("Invalid width for system DMA controller\n");
	return NULL;
    }

    PSYSTEM_DMA_ADAPTER SystemAdapter = &HalpDmaSystemAdapters[Desc->DmaChannel];
    if (!SystemAdapter->Handle) {
	NTSTATUS Status = WdmHalDmaOpenSystemAdapter(Desc->DmaChannel,
						     &SystemAdapter->Handle);
	if (!NT_SUCCESS(Status)) {
	    DPRINT("Unable to open system adapter for channel %d, err 0x%x\n",
		   Desc->DmaChannel, Status);
	    return NULL;
	}
    }
    assert(SystemAdapter->Handle != NULL);

    DMA_MODE DmaMode = { { 0 } };
    DmaMode.Channel = Desc->DmaChannel & 3;
    DmaMode.AutoInitialize = Desc->AutoInitialize;

    /*
     * Set the DMA request mode.
     *
     * For (E)ISA bus master devices we need to unmask (enable) the DMA
     * channel and set it to cascade mode. This requires IO accesses (via
     * READ_PORT_UCHAR etc) which necessitates a trip to the server.
     * Fortunately we don't support (E)ISA bus master devices so we don't
     * need to do this and can simply select the right one bases on the
     * specified device description.
     */
    if (Desc->DemandMode) {
	DmaMode.RequestMode = DEMAND_REQUEST_MODE;
    } else {
	DmaMode.RequestMode = SINGLE_REQUEST_MODE;
    }

    SystemAdapter->AdapterMode = DmaMode;
    SystemAdapter->Width16Bits = Controller == 2;

    return SystemAdapter;
}

/**
 * @name HalGetAdapter
 *
 * Create an adapter object for the given DMA device.
 *
 * @param DeviceDescription
 *        Structure describing the attributes of the device.
 * @param NumberOfMapRegisters
 *        On return this is filled with the maximum number of map registers the
 *        device driver can allocate for DMA transfer operations.
 *
 * @return The DMA adapter on success, NULL otherwise.
 *
 * @implemented
 *
 * @remarks This routine must be called at PASSIVE_LEVEL.
 */
NTAPI PDMA_ADAPTER HalGetAdapter(IN PDEVICE_DESCRIPTION DeviceDescription,
				 OUT PULONG NumberOfMapRegisters)
{
    PAGED_CODE();

    /* Validate parameters in device description */
    if (DeviceDescription->Version > DEVICE_DESCRIPTION_VERSION2) {
	return NULL;
    }
    /* Dma64BitAddresses implies Dma32BitAddresses */
    if (DeviceDescription->Dma64BitAddresses && !DeviceDescription->Dma32BitAddresses) {
	return NULL;
    }

    /*
     * See if we're going to use ISA DMA controller. We do not support EISA,
     * so only the first 8 channels are available. We also do not support ISA
     * bus mastering devices, so any request for a bus mastering adapter is
     * denied. Likewise, ISA devices can only access the lowest 16MB of RAM,
     * so 32-bit and 64-bit devices are rejected as well,
     *
     * We also disallow creating adapter for ISA/EISA DMA channel 4 since it's
     * used for cascading the controllers and not available for software use.
     */
    if (DeviceDescription->InterfaceType == Eisa) {
	DPRINT("Extended ISA is unsupported. Only ISA is supported.\n");
	return NULL;
    } else if (DeviceDescription->InterfaceType == Isa) {
	if (DeviceDescription->DmaChannel >= 8) {
	    DPRINT("Invalid DMA channel %d for ISA bus\n",
		   DeviceDescription->DmaChannel);
	    return NULL;
	}
	if (DeviceDescription->DmaChannel == 4) {
	    DPRINT("Invalid DMA channel %d for ISA bus\n",
		   DeviceDescription->DmaChannel);
	    return NULL;
	}
	if (DeviceDescription->Master) {
	    DPRINT("ISA bus mastering is unsupported.\n");
	    return NULL;
	}
	if (DeviceDescription->Dma32BitAddresses) {
	    DPRINT("ISA devices cannot not be 32-bit.\n");
	    return NULL;
	}
	if (DeviceDescription->Dma64BitAddresses) {
	    DPRINT("ISA devices cannot not be 64-bit.\n");
	    return NULL;
	}
    } else {
	/* For non-ISA devices, it must be able to access at least the lowest
	 * 4GB of physical memory. We reject the DMA operation if otherwise. */
	if (!DeviceDescription->Dma32BitAddresses) {
	    DPRINT("Non-ISA device (iface type %d) must be at least 32-bit.\n",
		   DeviceDescription->InterfaceType);
	    return NULL;
	}
    }

    /* Now allocate the adapter object */
    PADAPTER_OBJECT AdapterObject = ExAllocatePool(sizeof(ADAPTER_OBJECT));
    if (AdapterObject == NULL) {
	DPRINT("Unable to allocate adapter object.\n");
	return NULL;
    }

    /* Initialize the common DMA header */
    AdapterObject->DmaHeader.Version = (USHORT)DeviceDescription->Version;
    AdapterObject->DmaHeader.Size = sizeof(ADAPTER_OBJECT);
    AdapterObject->DmaHeader.DmaOperations = &HalpDmaOperations;

    /*
     * For first eight ISA/EISA channels we need to create the system DMA adapter
     * objects if they haven't been created yet.
     */
    if (DeviceDescription->InterfaceType == Isa) {
	AdapterObject->SystemAdapter = HalpDmaGetSystemAdapter(DeviceDescription);
	if (AdapterObject->SystemAdapter == NULL) {
	    ExFreePool(AdapterObject);
	    return NULL;
	}
    }

    /*
     * Setup the values in the adapter object that are common for all
     * types of buses.
     */
    AdapterObject->Dma64BitAddresses = DeviceDescription->Dma64BitAddresses;
    AdapterObject->ScatterGather = DeviceDescription->ScatterGather;

    /*
     * Calculate the maximum number of map registers the device can (or need
     * to) allocate. If the device does not support scatter-gather, or if we
     * are on a 64-bit system but the device can only access the lowest 4GB
     * of physical memory, then a contiguous intermediate buffer might be needed
     * depending whether the MDL is physically contiguous. In this case the
     * number of map registers we need is determined by the IO buffer's maximum
     * size, which is specified by the MaximumLength member of the device
     * description. Additionally, for ISA devices this is capped to 64KB because
     * the ISA DMA controller can only access one 64KB bank per DMA transfer.
     *
     * Otherwise, for ISA devices one map register is needed (for ISA devices,
     * supporting scatter gather means that the ISA DMA controller can be paused
     * between page transfers, so we will just transfer one page at a time),
     * and for PCI(E) devices no map register is needed.
     */
    ULONG MaximumLength = DeviceDescription->MaximumLength & MAXLONG;
    if (!DeviceDescription->ScatterGather ||
	(sizeof(PCHAR) == 8 && !DeviceDescription->Dma64BitAddresses)) {
	/*
	 * In the equation below the additional map register added by
	 * the "+1" accounts for the case when a transfer does not start
	 * at a page-aligned address.
	 */
	AdapterObject->MaxMapRegs = BYTES_TO_PAGES(MaximumLength) + 1;
	/* The ISA DMA controller cannot perform DMA transfers that cross the
	 * 64KB boundary, so in this case at most 16 map registers can be
	 * allocated. PCI devices do not have this limitation. */
	if (AdapterObject->SystemAdapter && AdapterObject->MaxMapRegs > 16) {
	    AdapterObject->MaxMapRegs = 16;
	}
    } else {
	AdapterObject->MaxMapRegs = (DeviceDescription->InterfaceType == Isa) ? 1 : 0;
    }

    if (AdapterObject->MaxMapRegs) {
	*NumberOfMapRegisters = AdapterObject->MaxMapRegs;
    } else {
	/* If the device does not need any map registers, the ReactOS implementation
	 * actually returns a non-zero value for the NumberOfMapRegisters parameter
	 * despite the fact that future DMA operations will ignore this parameter.
	 * I'm not sure why this is needed but it seems that some drivers expect
	 * this to be non-zero, so we will follow the ReactOS implementation here. */
	*NumberOfMapRegisters = BYTES_TO_PAGES(MaximumLength) + 1;
    }

    InitializeListHead(&AdapterObject->MapRegisterList);
    InsertTailList(&HalpDmaAdapterList, &AdapterObject->Link);

    return &AdapterObject->DmaHeader;
}

/**
 * @name HalpGetAdapterMaximumPhysicalAddress
 *
 * Determine the maximal physical address that an adapter object can access.
 * The DMA subsystem can the use this information to allocate the correct
 * intermediate buffers if the device needs double buffering for DMA.
 *
 * @remarks
 *    Note that on 64bit systems, if a PCI device needs double buffering we
 *    will only use the lowest 4GB of physical memory as intermediate buffers.
 *    This appears to be the Windows behavior and is indeed what ReactOS
 *    implements. My guess for the reason behind this is that although the
 *    device driver author has indicated that the device supports 64-bit
 *    addressing, possibly from reading its datasheet, it is sometimes the
 *    case that the manufacturer didn't actually implement 64-bit addressing
 *    properly (despite what the datasheet might have claimed). So our guess
 *    is that because the dominant form of PCI(E) DMA is scatter/gather bus
 *    mastering DMA, if the hardware manufacturer didn't bother to implement
 *    scatter/gather (the only case for a 64-bit-capable PCI device to need
 *    map registers), then it probably did a half-assed job implementing
 *    64-bit addressing as well, so let's play it safe. If this proves to be
 *    unnecessary, we can always change it.
 */
static PHYSICAL_ADDRESS HalpGetAdapterMaximumPhysicalAddress(IN PADAPTER_OBJECT Adpt)
{
    PHYSICAL_ADDRESS Addr = { .QuadPart = 0xFFFFFF };
    if (!Adpt->SystemAdapter) {
	Addr.QuadPart = (!Adpt->MaxMapRegs && Adpt->Dma64BitAddresses) ?
	    0xFFFFFFFFFFFFFFFFULL : 0xFFFFFFFF;
    }
    return Addr;
}

/**
 * @name HalpGetAdapterBoundaryAddressBits
 *
 * Determine the maximum size (in bits) of physically contiguous memory
 * that the adapter can access in a single DMA transfer. For ISA slave DMA
 * devices the 64KB boundary mustn't be crossed since the ISA DMA controller
 * wouldn't be able to handle it. For PCI bus-master DMA devices the buffer
 * mustn't cross the 4GB boundary. I don't quite understand the reasoning
 * behind the latter limitation (it seems to me that 64-bit PCI devices can
 * cross the 4GB boundary just fine), but this is what ReactOS does so I'm
 * going to follow ReactOS. If this proves to be too limiting, we can always
 * change it.
 */
static ULONG HalpGetAdapterBoundaryAddressBits(IN PADAPTER_OBJECT Adpt)
{
    return Adpt->SystemAdapter ? 16 : 32;
}

/**
 * @name HalpAllocateMapRegisters
 *
 * Allocate map registers for DMA adapter.
 *
 * @param AdapterObject
 *        Adapter object to allocate map registers for.
 * @param Count
 *        Number of contiguous 4K pages to allocate
 * @param pMapReg
 *        On success, returns the allocated map register object
 */
static NTSTATUS HalpAllocateMapRegisters(IN PADAPTER_OBJECT AdapterObject,
					 IN ULONG Count,
					 OUT PMAP_REGISTER_ENTRY *pMapReg)
{
    assert(AdapterObject != NULL);
    IopAllocateObject(MapReg, MAP_REGISTER_ENTRY);
    PHYSICAL_ADDRESS HighestAddr = HalpGetAdapterMaximumPhysicalAddress(AdapterObject);

    /* Check if there are free map registers. Note that since the list is ordered
     * by physical address (lower physical address first), as soon as we found a
     * suitable map register entry we can terminate the loop. */
    ReverseLoopOverList(Entry, &HalpDmaMapRegCtrl.List, MAP_REGISTER_ENTRY, Link) {
	ULONGLONG EndAddr = Entry->PhyBase.QuadPart + ((ULONGLONG)Count << PAGE_SHIFT);
	if (!Entry->AssignedAdapter && (Entry->Count >= Count) &&
	    (HighestAddr.QuadPart < EndAddr)) {
	    /* Found one. Split the map register entry if there are left overs */
	    if (Entry->Count > Count) {
		ULONGLONG LeftOver = ((ULONGLONG)Entry->Count - Count) << PAGE_SHIFT;
		Entry->Count -= Count;
		/* Insert MapReg after Entry */
		InsertHeadList(&Entry->Link, &MapReg->Link);
		MapReg->VirtBase = (PVOID)((ULONG_PTR)Entry->VirtBase + LeftOver);
		MapReg->PhyBase.QuadPart = Entry->PhyBase.QuadPart + LeftOver;
		MapReg->Count = Count;
	    } else {
		ExFreePool(MapReg);
		MapReg = Entry;
	    }
	    /* Assign the map register to the adapter object */
	    MapReg->AssignedAdapter = AdapterObject;
	    InsertHeadList(&AdapterObject->MapRegisterList, &MapReg->AdapterLink);
	    *pMapReg = MapReg;
	    return STATUS_SUCCESS;
	}
    }

    /* No more free map registers. We must now request the server to allocate
     * new map registers. The server will always try to allocate high memory
     * when it's available, so as not to waste scarce resource (low memory). */
    ULONG BoundAddrBits = HalpGetAdapterBoundaryAddressBits(AdapterObject);
    RET_ERR_EX(WdmHalAllocateDmaBuffer(Count << PAGE_SHIFT, &HighestAddr,
				       BoundAddrBits, MmCached,
				       &MapReg->VirtBase, &MapReg->PhyBase),
	       ExFreePool(MapReg));
    assert(MapReg->VirtBase != NULL);
    assert(MapReg->PhyBase.QuadPart != 0);

    /* Setup the map register entry for the buffer allocated. Note we keep the
     * list of all map registers ordered by their physical address. */
    PLIST_ENTRY Node = &HalpDmaMapRegCtrl.List;
    LoopOverList(Entry, &HalpDmaMapRegCtrl.List, MAP_REGISTER_ENTRY, Link) {
	if (Entry->PhyBase.QuadPart > MapReg->PhyBase.QuadPart) {
	    Node = &Entry->Link;
	    break;
	}
    }
    InsertTailList(Node, &MapReg->Link);
    InsertHeadList(&AdapterObject->MapRegisterList, &MapReg->AdapterLink);
    MapReg->AssignedAdapter = AdapterObject;
    MapReg->Count = Count;
    *pMapReg = MapReg;

    return STATUS_SUCCESS;
}

/**
 * @name HalpFreeMapRegisters
 *
 * Free map registers reserved by the system for a DMA. Note that this
 * is the exported (via DMA_OPERATIONS) function that the driver should
 * call if its map register callback returns DeallocateObjectKeepRegisters.
 *
 * @param AdapterObject
 *        DMA adapter to free map registers on.
 * @param MapRegisterBase
 *        Handle to map registers to free. This must match the value passed
 *        to the map register callback in AllocateAdapterChannel.
 * @param NumberOfRegisters
 *        Number of map registers to be freed. This value must match the number
 *        specified in an earlier call to AllocateAdapterChannel.
 *
 * @implemented
 */
NTAPI VOID HalpFreeMapRegisters(IN PDMA_ADAPTER DmaAdapter,
				IN PVOID MapRegisterBase,
				IN ULONG NumberOfMapRegisters)
{
    PMAP_REGISTER_ENTRY MapReg = (PMAP_REGISTER_ENTRY)MapRegisterBase;
    assert((PADAPTER_OBJECT)DmaAdapter == MapReg->AssignedAdapter);
    assert(NumberOfMapRegisters == MapReg->Count);
    /* Detach the map register from the adapter map register list */
    RemoveEntryList(&MapReg->AdapterLink);
    MapReg->AssignedAdapter = NULL;
    MapReg->Keep = FALSE;

    /* Merge the adjacent free map registers. Note that both the virtual
     * address windows and physical address windows must be adjacent. */
    PMAP_REGISTER_ENTRY Prev = GetPrevEntryList(&MapReg->Link, MAP_REGISTER_ENTRY,
						Link, &HalpDmaMapRegCtrl.List);
    if (Prev != NULL && !Prev->AssignedAdapter &&
	(Prev->VirtBase + ((ULONG_PTR)Prev->Count << PAGE_SHIFT) == MapReg->VirtBase) &&
	(Prev->PhyBase.QuadPart + ((ULONGLONG)Prev->Count << PAGE_SHIFT) == MapReg->PhyBase.QuadPart)) {
	assert(!Prev->Keep);
	RemoveEntryList(&Prev->Link);
	MapReg->VirtBase = Prev->VirtBase;
	MapReg->PhyBase = Prev->PhyBase;
	MapReg->Count += Prev->Count;
	ExFreePool(Prev);
    }

    PMAP_REGISTER_ENTRY Next = GetNextEntryList(&MapReg->Link, MAP_REGISTER_ENTRY,
						Link, &HalpDmaMapRegCtrl.List);
    if (Next != NULL && !Next->AssignedAdapter &&
	(MapReg->VirtBase + ((ULONG_PTR)MapReg->Count << PAGE_SHIFT) == Next->VirtBase) &&
	(MapReg->PhyBase.QuadPart + ((ULONGLONG)MapReg->Count << PAGE_SHIFT) == Next->PhyBase.QuadPart)) {
	assert(!Next->Keep);
	RemoveEntryList(&Next->Link);
	MapReg->Count += Next->Count;
	ExFreePool(Next);
    }
}

/**
 * @name HalpAllocateCommonBuffer
 *
 * Allocates memory that is visible to both the processor(s) and the DMA
 * device. Note that the buffers allocated by this function aren't freed
 * when the adapter object is released (via FreeAdapterChannel). The only
 * way to free the buffers allocated here is by calling FreeCommonBuffer.
 *
 * @param AdapterObject
 *        Adapter object to allocate the common buffer for.
 * @param Length
 *        Number of bytes to allocate.
 * @param PhysicalAddress
 *        Physical address the driver can use to access the buffer.
 * @param CacheEnabled
 *        Specifies if the memory can be cached. According to Microsoft, on
 *        real NT systems this parameter is ignored. The operating system
 *        determines whether to enable cached memory in the common buffer
 *        that is to be allocated. That decision is based on the processor
 *        architecture and device bus. On i386 and amd64 cached memory is
 *        always enabled and it is assumed that all DMA operations performed
 *        by a device are coherent with the relevant CPU caches, which might
 *        be caching that memory. On arm and arm64, the operating system does
 *        not automatically enable cached memory for all devices and relies
 *        on the ACPI_CCA method for each device to determine whether the
 *        device is cache-coherent.
 *
 *        Since we only support i386 and amd64, we will follow NT and ignore
 *        this parameter. On Windows, if driver needs to disable caching, it
 *        will call AllocateCommonBufferEx instead. This function is not yet
 *        implemented on Neptune OS.
 *
 * @return The base virtual address of the memory allocated or NULL on failure.
 *
 * @see HalpFreeCommonBuffer
 *
 * @implemented
 */
NTAPI PVOID HalpAllocateCommonBuffer(IN PDMA_ADAPTER DmaAdapter,
				     IN ULONG Length,
				     OUT PPHYSICAL_ADDRESS PhysicalAddress,
				     IN BOOLEAN CacheEnabled)
{
    UNREFERENCED_PARAMETER(CacheEnabled);
    PADAPTER_OBJECT AdapterObject = (PADAPTER_OBJECT)DmaAdapter;

    PMAP_REGISTER_ENTRY MapReg = NULL;
    if (!NT_SUCCESS(HalpAllocateMapRegisters(AdapterObject,
					     PAGE_ROUND_UP(Length) >> PAGE_SHIFT,
					     &MapReg))) {
	return NULL;
    }
    assert(MapReg != NULL);
    /* Mark the map reg as Keep so it won't get freed by FreeAdapterChannel */
    MapReg->Keep = TRUE;
    *PhysicalAddress = MapReg->PhyBase;

    return MapReg->VirtBase;
}

/**
 * @name HalpFreeCommonBuffer
 *
 * Free common buffer allocated with HalpAllocateCommonBuffer.
 *
 * @see HalpAllocateCommonBuffer
 *
 * @implemented
 */
NTAPI VOID HalpFreeCommonBuffer(IN PDMA_ADAPTER DmaAdapter,
				IN ULONG Length,
				IN PHYSICAL_ADDRESS PhysicalAddress,
				IN PVOID VirtualAddress,
				IN BOOLEAN CacheEnabled)
{
    PADAPTER_OBJECT AdapterObject = (PADAPTER_OBJECT)DmaAdapter;
    LoopOverList(MapReg, &AdapterObject->MapRegisterList,
		 MAP_REGISTER_ENTRY, AdapterLink) {
	if (MapReg->VirtBase == VirtualAddress) {
	    assert(MapReg->PhyBase.QuadPart == PhysicalAddress.QuadPart);
	    assert(MapReg->Count == (PAGE_ROUND_UP(Length) << PAGE_SHIFT));
	    HalpFreeMapRegisters(DmaAdapter, MapReg, MapReg->Count);
	}
    }
    assert(FALSE);
}

/**
 * @name HalpAllocateAdapterChannel
 *
 * Setup map registers for an adapter object.
 *
 * @param AdapterObject
 *        Pointer to an ADAPTER_OBJECT to set up.
 * @param DeviceObject
 *        Device object to allocate adapter channel for.
 * @param NumberOfMapRegisters
 *        Number of map registers requested.
 * @param ExecutionRoutine
 *        Callback to call when map registers are allocated.
 * @param Context
 *        Context to be used with ExecutionRoutine.
 *
 * @return
 *    If not enough map registers can be allocated then the error
 *    STATUS_INSUFFICIENT_RESOURCES is returned. If the function
 *    succeeds or the callback is queued for later delivering then
 *    STATUS_SUCCESS is returned.
 *
 * @see HalpFreeAdapterChannel
 *
 * @implemented
 */
NTAPI NTSTATUS HalpAllocateAdapterChannel(IN PDMA_ADAPTER DmaAdapter,
					  IN PDEVICE_OBJECT DeviceObject,
					  IN ULONG NumberOfMapRegisters,
					  IN PDRIVER_CONTROL ExecutionRoutine,
					  IN PVOID Context)
{
    PADAPTER_OBJECT AdapterObject = (PADAPTER_OBJECT)DmaAdapter;
    if (!AdapterObject || !DeviceObject || !ExecutionRoutine) {
	return STATUS_INVALID_PARAMETER;
    }

    PMAP_REGISTER_ENTRY MapReg = NULL;
    if (NumberOfMapRegisters && AdapterObject->MaxMapRegs) {
	if (NumberOfMapRegisters > AdapterObject->MaxMapRegs) {
	    return STATUS_INSUFFICIENT_RESOURCES;
	}
	RET_ERR(HalpAllocateMapRegisters(AdapterObject, NumberOfMapRegisters, &MapReg));
	assert(MapReg != NULL);
    }

    ULONG Result = ExecutionRoutine(DeviceObject, DeviceObject->CurrentIrp,
				    MapReg, Context);

    /*
     * Possible return values:
     *
     * - KeepObject
     *   Don't free any resources, the ADAPTER_OBJECT is still in use and
     *   the caller will call HalpFreeAdapterChannel later.
     *
     * - DeallocateObject
     *   Deallocate the map registers and release the ADAPTER_OBJECT, so
     *   someone else can use it.
     *
     * - DeallocateObjectKeepRegisters
     *   Release the ADAPTER_OBJECT, but hang on to the map registers. The
     *   client will later call HalpFreeMapRegisters.
     *
     * NOTE:
     * HalpFreeAdapterChannel runs the queue, so it must be called unless
     * the adapter object is not to be freed.
     */
    if (Result == DeallocateObject) {
	HalpFreeAdapterChannel(DmaAdapter);
    } else if (Result == DeallocateObjectKeepRegisters) {
	if (MapReg) {
	    MapReg->Keep = TRUE;
	}
	HalpFreeAdapterChannel(DmaAdapter);
    }

    return STATUS_SUCCESS;
}

/**
 * @name HalpFreeAdapterChannel
 *
 * Free DMA resources allocated by HalpAllocateAdapterChannel.
 *
 * @param AdapterObject
 *        Adapter object with resources to free.
 *
 * @remarks
 *    This function releases map registers assigned to the DMA adapter,
 *    unless the map register is marked as Keep.
 *
 * @see HalpAllocateAdapterChannel
 *
 * @implemented
 */
NTAPI VOID HalpFreeAdapterChannel(IN PDMA_ADAPTER DmaAdapter)
{
    PADAPTER_OBJECT AdapterObject = (PADAPTER_OBJECT)DmaAdapter;
    LoopOverList(MapReg, &AdapterObject->MapRegisterList,
		 MAP_REGISTER_ENTRY, AdapterLink) {
	/*
	 * If the map register callback returned DeallocateObjectKeepRegisters,
	 * or if the common buffer was allocated by AllocateCommonBuffer, then
	 * MapReg->Keep will be set to TRUE and in this case we don't free the
	 * map register here. Driver code will free it later.
	 */
	if (!MapReg->Keep) {
	    HalpFreeMapRegisters(DmaAdapter, MapReg, MapReg->Count);
	}
    }
}

/**
 * @name HalpGetDmaAdapter
 *
 * Internal routine to allocate PnP DMA adapter object. It's exported through
 * HalDispatchTable and used by IoGetDmaAdapter.
 *
 * @see HalGetAdapter
 */
NTAPI PDMA_ADAPTER HalpGetDmaAdapter(IN PVOID Context,
				     IN PDEVICE_DESCRIPTION DeviceDescription,
				     OUT PULONG NumberOfMapRegisters)
{
    return HalGetAdapter(DeviceDescription, NumberOfMapRegisters);
}

/**
 * @name HalpPutDmaAdapter
 *
 * Internal routine to free DMA adapter and resources for reuse. It's exported
 * using the DMA_OPERATIONS interface by HalGetAdapter.
 *
 * @see HalGetAdapter
 */
NTAPI VOID HalpPutDmaAdapter(IN PDMA_ADAPTER DmaAdapter)
{
    PADAPTER_OBJECT AdapterObject = (PADAPTER_OBJECT)DmaAdapter;
    RemoveEntryList(&AdapterObject->Link);
    HalpFreeAdapterChannel(DmaAdapter);
    ExFreePool(AdapterObject);
}

/**
 * @name HalpCopyBufferMap
 *
 * Helper function for copying data from/to map register buffers.
 *
 * @param Mdl
 *        MDL to copy data to/from.
 * @param MapReg
 *        Map register to copy data from/to.
 * @param CurrentVa
 *        Index into the specified Mdl indicating the start of the transfer.
 * @param Length
 *        Length of the data being copied. CurrentVa + Length should
 *        not exceed the end of the MDL.
 * @param WriteToDevice
 *        If FALSE (meaning that we are reading from the device), data
 *        will be copied from the map registers to the MDL. Otherwise,
 *        data will be copied from the MDL to the map registers.
 *
 * @see HalpMapTransfer, HalpFlushAdapterBuffers
 */
NTAPI VOID HalpCopyBufferMap(IN PMDL Mdl,
			     IN PMAP_REGISTER_ENTRY MapReg,
			     IN PVOID CurrentVa,
			     IN ULONG Length,
			     IN BOOLEAN WriteToDevice)
{
    DbgTrace("MdlSystemVa = %p CurrentVa = %p Length = 0x%x WriteToDevice = %d\n",
	     MmGetSystemAddressForMdlSafe(Mdl), CurrentVa, Length, WriteToDevice);
    /* Compute the offset of CurrentVa against the start of the MDL. */
    ULONG_PTR OffsetInMdl = (ULONG_PTR)CurrentVa - (ULONG_PTR)MmGetMdlVirtualAddress(Mdl);
    ULONG_PTR CurrentAddress = (ULONG_PTR)MmGetSystemAddressForMdl(Mdl) + OffsetInMdl;
    PVOID MapRegBase = (PVOID)((ULONG_PTR)MapReg->VirtBase);
    assert(OffsetInMdl + Length <= Mdl->ByteCount);

    if (WriteToDevice) {
	DbgTrace("Copying 0x%x bytes from buffer %p to map reg %p\n", Length,
		 (PVOID)CurrentAddress, MapRegBase);
	RtlCopyMemory(MapRegBase, (PVOID)CurrentAddress, Length);
    } else {
	DbgTrace("Copying 0x%x bytes from map reg %p to buffer %p\n", Length,
		 MapRegBase, (PVOID)CurrentAddress);
	RtlCopyMemory((PVOID)CurrentAddress, MapRegBase, Length);
    }
}

/**
 * @name HalpMapTransfer
 *
 * Map a DMA for transfer and do the DMA if it's a slave.
 *
 * @param AdapterObject
 *        Adapter object to do the DMA on. Bus-master may pass NULL.
 * @param Mdl
 *        MDL for the IO buffer to DMA in to or out of.
 * @param MapRegisterBase
 *        Handle to map registers to use for this dma.
 * @param CurrentVa
 *        Index into Mdl to transfer into/out of.
 * @param Length
 *        Length of the DMA transfer. This will be updated to the number
 *        of bytes actually transferred by this function.
 * @param WriteToDevice
 *        TRUE if it's an output DMA, FALSE otherwise.
 *
 * @return
 *    A physical address that can be used to program a DMA controller. It's
 *    not meaningful for slave DMA device.
 *
 * @remarks
 *    This function does a copyover to physically contiguous memory represented
 *    by the map registers if needed. If the buffer described by MDL can be
 *    used as is then no copyover is done. If it's a slave transfer, this
 *    function actually performs it.
 *
 * @implemented
 */
NTAPI PHYSICAL_ADDRESS HalpMapTransfer(IN PDMA_ADAPTER DmaAdapter,
				       IN PMDL Mdl,
				       IN PVOID MapRegisterBase,
				       IN PVOID CurrentVa,
				       IN OUT PULONG Length,
				       IN BOOLEAN WriteToDevice)
{
    PADAPTER_OBJECT AdapterObject = (PADAPTER_OBJECT)DmaAdapter;
    assert(AdapterObject != NULL);

    /* Physical address corresponding to the transfer start page and offset. */
    PHYSICAL_ADDRESS PhysicalAddress = MmGetMdlPhysicalAddress(Mdl, CurrentVa);

    /* Calculate the maximum possible size of one single DMA transfer. This
     * consists of pages that are physically contiguous and don't cross the
     * adapter boundary (64KB for ISA controllers and 4GB for PCI devices). */
    ULONG BoundAddrBits = HalpGetAdapterBoundaryAddressBits(AdapterObject);
    ULONG TransferLength = MmGetMdlPhysicallyContiguousSize(Mdl, CurrentVa,
							    BoundAddrBits);

    /* Special case for bus master adapters with S/G support. We can directly
     * use the buffer specified by the MDL, so not much work has to be done.
     * Just return the passed VA's corresponding physical address and update
     * length to the number of physically contiguous bytes found. */
    if (MapRegisterBase == NULL) {
	if (TransferLength < *Length)
	    *Length = TransferLength;
	return PhysicalAddress;
    }

    /*
     * The code below applies to slave DMA adapters and bus master adapters
     * without hardware S/G support. Both of these may require map registers.
     */
    PMAP_REGISTER_ENTRY MapReg = (PMAP_REGISTER_ENTRY)MapRegisterBase;

    /*
     * Determine whether we actually need map registers.
     *
     * If we're about to simulate software S/G and not all the pages are
     * physically contiguous then we must use the map registers to store
     * the data and allow the whole transfer to proceed at once.
     *
     * Otherwise, if the physical address of the MDL buffer exceeds the
     * highest physical address limit of the device, we must likewise use
     * map registers as an intermediate buffer.
     *
     * If neither of the above is true, then no map register is needed.
     */
    AdapterObject->UseMapRegisters = FALSE;
    if (!AdapterObject->ScatterGather && (TransferLength < *Length)) {
	AdapterObject->UseMapRegisters = TRUE;
    } else {
	PHYSICAL_ADDRESS HighAddr = HalpGetAdapterMaximumPhysicalAddress(AdapterObject);
	if ((PhysicalAddress.QuadPart + TransferLength) > HighAddr.QuadPart) {
	    AdapterObject->UseMapRegisters = TRUE;
	}
    }

    /* If we are using map registers, update the physical address and
     * determine the new maximum possible transfer length. */
    if (AdapterObject->UseMapRegisters) {
	PhysicalAddress = MapReg->PhyBase;
	TransferLength = MapReg->Count * PAGE_SIZE;
    }

    /* If the maximum transfer length exceeds what the caller needs to
     * transfer, cap it to the user specified length. */
    if (TransferLength > *Length) {
	TransferLength = *Length;
    }

    /* If we decided to use the map registers (see above) and we're about
     * to transfer data to the device then copy the buffers into the map
     * register memory. */
    if (AdapterObject->UseMapRegisters && WriteToDevice) {
	HalpCopyBufferMap(Mdl, MapReg, CurrentVa, TransferLength, WriteToDevice);
    }

    /* Return the length of transfer that actually takes place. */
    *Length = TransferLength;

    /* If we're doing slave (system) DMA, program the (E)ISA controller
     * to actually start the transfer. */
    if (AdapterObject->SystemAdapter) {
	DMA_MODE AdapterMode = AdapterObject->SystemAdapter->AdapterMode;

	if (WriteToDevice) {
	    AdapterMode.TransferType = WRITE_TRANSFER;
	} else {
	    AdapterMode.TransferType = READ_TRANSFER;
	    RtlZeroMemory((PUCHAR)MapReg->VirtBase, TransferLength);
	}

	USHORT TransferOffset = (USHORT)PhysicalAddress.LowPart;
	if (AdapterObject->SystemAdapter->Width16Bits) {
	    TransferLength >>= 1;
	    TransferOffset >>= 1;
	}

	assert(TransferLength != 0);
	assert((TransferLength >> 16) == 0);
	assert((PhysicalAddress.LowPart >> 24) == 0);
	assert(PhysicalAddress.HighPart == 0);
	/* Call the server to start the DMA transfer. */
	WdmHalDmaStartTransfer(AdapterObject->SystemAdapter->Handle, AdapterMode.Byte,
			       TransferOffset, TransferLength,
			       PhysicalAddress.LowPart >> 16);
    }

    /* Return physical address of the buffer with data that is used for the
     * transfer. It can either point inside the Mdl that was passed by the
     * caller or into the map registers if the Mdl buffer can't be used
     * directly. */
    return PhysicalAddress;
}

/**
 * @name HalpFlushAdapterBuffers
 *
 * Flush any data remaining in the DMA controller's memory into the host
 * memory.
 *
 * @param AdapterObject
 *        The adapter object to flush.
 * @param Mdl
 *        Original MDL to flush data into.
 * @param MapReg
 *        Map register entry that was just used by HalpMapTransfer, etc.
 * @param CurrentVa
 *        Offset into Mdl to be flushed into, same as was passed to
 *        HalpMapTransfer.
 * @param Length
 *        Length of the buffer to be flushed into.
 * @param WriteToDevice
 *        TRUE if it's a write, FALSE if it's a read.
 *
 * @return TRUE in all cases.
 *
 * @remarks
 *    This copies data from the map register-backed buffer to the user's
 *    target buffer. Data are not in the user buffer until this function
 *    is called.
 *    For slave DMA transfers the controller channel is masked effectively
 *    stopping the current transfer.
 *
 * @implemented.
 */
NTAPI BOOLEAN HalpFlushAdapterBuffers(IN PDMA_ADAPTER DmaAdapter,
				      IN PMDL Mdl,
				      IN PVOID MapReg,
				      IN PVOID CurrentVa,
				      IN ULONG Length,
				      IN BOOLEAN WriteToDevice)
{
    PADAPTER_OBJECT AdapterObject = (PADAPTER_OBJECT)DmaAdapter;
    ASSERT(AdapterObject);

    KeFlushIoBuffers(Mdl, !WriteToDevice, TRUE);

    /* No map register is needed. Simply return. Note that this can never
     * happen for slave DMA. */
    if (MapReg == NULL)
	return TRUE;

    /* If we are doing slave DMA, mask out (disable) the DMA channel. */
    if (AdapterObject->SystemAdapter) {
	WdmHalDmaDisableChannel(AdapterObject->SystemAdapter->Handle);
    }

    /* We only need to flush the map registers if we are reading from a device. */
    if (AdapterObject->UseMapRegisters && !WriteToDevice) {
	HalpCopyBufferMap(Mdl, (PMAP_REGISTER_ENTRY)MapReg, CurrentVa, Length, FALSE);
    }

    return TRUE;
}

/**
 * @name HalpFlushCommonBuffer
 *
 * @implemented
 */
NTAPI BOOLEAN HalpFlushCommonBuffer(IN PDMA_ADAPTER DmaAdapter,
				    IN ULONG Length,
				    IN PHYSICAL_ADDRESS PhysicalAddress,
				    IN PVOID VirtualAddress)
{
    /* Function always returns true */
    return TRUE;
}

/**
 * @name HalpDmaGetDmaAlignment
 *
 * Internal routine to return the DMA alignment requirement. It's exported
 * using the DMA_OPERATIONS interface by HalGetAdapter.
 *
 * @see HalGetAdapter
 */
NTAPI ULONG HalpDmaGetDmaAlignment(IN PDMA_ADAPTER DmaAdapter)
{
    return 1;
}

/**
 * @name HalpReadDmaCounter
 *
 * Read DMA operation progress counter.
 *
 * @implemented
 */
NTAPI ULONG HalpReadDmaCounter(IN PDMA_ADAPTER DmaAdapter)
{
    PADAPTER_OBJECT AdapterObject = (PADAPTER_OBJECT)DmaAdapter;
    if (!AdapterObject->SystemAdapter) {
	return 0;
    }

    ULONG Count = 0;
    WdmHalDmaReadProgressCounter(AdapterObject->SystemAdapter->Handle, &Count);

    Count++;
    Count &= 0xffff;
    if (AdapterObject->SystemAdapter->Width16Bits)
	Count *= 2;

    return Count;
}

typedef struct _SCATTER_GATHER_CONTEXT {
    BOOLEAN UsingUserBuffer;
    PDMA_ADAPTER AdapterObject;
    PMDL Mdl;
    PUCHAR CurrentVa;
    ULONG Length;
    PDRIVER_LIST_CONTROL AdapterListControlRoutine;
    PVOID AdapterListControlContext, MapRegisterBase;
    ULONG MapRegisterCount;
    BOOLEAN WriteToDevice;
} SCATTER_GATHER_CONTEXT, *PSCATTER_GATHER_CONTEXT;

NTAPI IO_ALLOCATION_ACTION HalpScatterGatherAdapterControl(IN PDEVICE_OBJECT DeviceObject,
							   IN PIRP Irp,
							   IN PVOID MapRegisterBase,
							   IN PVOID Context)
{
    PSCATTER_GATHER_CONTEXT AdapterControlContext = Context;
    PDMA_ADAPTER AdapterObject = AdapterControlContext->AdapterObject;
    ULONG ElementCount = 0, RemainingLength = AdapterControlContext->Length;
    PUCHAR CurrentVa = AdapterControlContext->CurrentVa;

    /* Store the map register base for later in HalpPutScatterGatherList */
    AdapterControlContext->MapRegisterBase = MapRegisterBase;

    SCATTER_GATHER_ELEMENT TempElements[MAX_SG_ELEMENTS];
    while (RemainingLength > 0 && ElementCount < MAX_SG_ELEMENTS) {
	TempElements[ElementCount].Length = RemainingLength;
	TempElements[ElementCount].Reserved = 0;
	TempElements[ElementCount].Address =
	    HalpMapTransfer(AdapterObject, AdapterControlContext->Mdl, MapRegisterBase,
			    CurrentVa + AdapterControlContext->Length - RemainingLength,
			    &TempElements[ElementCount].Length,
			    AdapterControlContext->WriteToDevice);
	if (TempElements[ElementCount].Length == 0)
	    break;

	DPRINT("Allocated one S/G element: 0x%llu with length: 0x%x\n",
	       TempElements[ElementCount].Address.QuadPart,
	       TempElements[ElementCount].Length);

	ASSERT(TempElements[ElementCount].Length <= RemainingLength);
	RemainingLength -= TempElements[ElementCount].Length;
	ElementCount++;
    }

    if (RemainingLength > 0) {
	DPRINT1("Scatter/gather list construction failed!\n");
	return DeallocateObject;
    }

    PSCATTER_GATHER_LIST ScatterGatherList =
	ExAllocatePoolWithTag(sizeof(SCATTER_GATHER_LIST) +
			      sizeof(SCATTER_GATHER_ELEMENT) * ElementCount,
			      TAG_DMA);
    ASSERT(ScatterGatherList);

    ScatterGatherList->NumberOfElements = ElementCount;
    ScatterGatherList->Reserved = (ULONG_PTR) AdapterControlContext;
    RtlCopyMemory(ScatterGatherList->Elements, TempElements,
		  sizeof(SCATTER_GATHER_ELEMENT) * ElementCount);

    DPRINT("Initiating S/G DMA with %d element(s)\n", ElementCount);

    AdapterControlContext->AdapterListControlRoutine(DeviceObject, Irp, ScatterGatherList,
						     AdapterControlContext->AdapterListControlContext);

    return DeallocateObjectKeepRegisters;
}

NTAPI NTSTATUS HalpCalculateScatterGatherListSize(IN PDMA_ADAPTER DmaAdapter,
						  IN PMDL Mdl OPTIONAL,
						  IN PVOID CurrentVa,
						  IN ULONG Length,
						  OUT PULONG ScatterGatherListSize,
						  OUT PULONG pNumberOfMapRegisters)
{
    ULONG NumberOfMapRegisters;
    ULONG SgSize;

    NumberOfMapRegisters = PAGE_ROUND_UP(Length) >> PAGE_SHIFT;
    SgSize = sizeof(SCATTER_GATHER_CONTEXT);

    *ScatterGatherListSize = SgSize;
    if (pNumberOfMapRegisters)
	*pNumberOfMapRegisters = NumberOfMapRegisters;

    return STATUS_SUCCESS;
}

/**
 * @name HalpBuildScatterGatherList
 *
 * Creates a scatter-gather list to be using in scatter/gather DMA
 *
 * @param DmaAdapter
 *        Adapter object representing the bus master or system dma controller.
 * @param DeviceObject
 *        The device target for DMA.
 * @param Mdl
 *        The MDL that describes the buffer to be mapped.
 * @param CurrentVa
 *        The current VA in the buffer to be mapped for transfer.
 * @param Length
 *        Specifies the length of data in bytes to be mapped.
 * @param ExecutionRoutine
 *        A caller supplied AdapterListControl routine to be called when DMA is available.
 * @param Context
 *        Context passed to the AdapterListControl routine.
 * @param WriteToDevice
 *        Indicates direction of DMA operation.
 *
 * @param ScatterGatherBuffer
 *        User buffer for the scatter-gather list
 *
 * @param ScatterGatherBufferLength
 *        Buffer length
 *
 * @return The status of the operation.
 *
 * @see HalpPutScatterGatherList
 *
 * @implemented
 */
NTAPI NTSTATUS HalpBuildScatterGatherList(IN PDMA_ADAPTER DmaAdapter,
					  IN PDEVICE_OBJECT DeviceObject,
					  IN PMDL Mdl,
					  IN PVOID CurrentVa,
					  IN ULONG Length,
					  IN PDRIVER_LIST_CONTROL ExecutionRoutine,
					  IN PVOID Context,
					  IN BOOLEAN WriteToDevice,
					  IN PVOID ScatterGatherBuffer,
					  IN ULONG ScatterGatherBufferLength)
{
    NTSTATUS Status;
    ULONG SgSize, NumberOfMapRegisters;
    PSCATTER_GATHER_CONTEXT ScatterGatherContext;
    BOOLEAN UsingUserBuffer;

    Status = HalpCalculateScatterGatherListSize(DmaAdapter, Mdl, CurrentVa, Length,
						&SgSize, &NumberOfMapRegisters);
    if (!NT_SUCCESS(Status))
	return Status;

    if (ScatterGatherBuffer) {
	/* Checking if user buffer is enough */
	if (ScatterGatherBufferLength < SgSize) {
	    return STATUS_BUFFER_TOO_SMALL;
	}
	UsingUserBuffer = TRUE;
    } else {
	ScatterGatherBuffer = ExAllocatePoolWithTag(SgSize, TAG_DMA);
	if (!ScatterGatherBuffer) {
	    return STATUS_INSUFFICIENT_RESOURCES;
	}
	UsingUserBuffer = FALSE;
    }

    ScatterGatherContext = (PSCATTER_GATHER_CONTEXT)ScatterGatherBuffer;

    /* Fill the scatter-gather context */
    ScatterGatherContext->UsingUserBuffer = UsingUserBuffer;
    ScatterGatherContext->AdapterObject = DmaAdapter;
    ScatterGatherContext->Mdl = Mdl;
    ScatterGatherContext->CurrentVa = CurrentVa;
    ScatterGatherContext->Length = Length;
    ScatterGatherContext->MapRegisterCount = NumberOfMapRegisters;
    ScatterGatherContext->AdapterListControlRoutine = ExecutionRoutine;
    ScatterGatherContext->AdapterListControlContext = Context;
    ScatterGatherContext->WriteToDevice = WriteToDevice;

    Status = HalpAllocateAdapterChannel(DmaAdapter,
					DeviceObject,
					NumberOfMapRegisters,
					HalpScatterGatherAdapterControl,
					ScatterGatherContext);

    if (!NT_SUCCESS(Status)) {
	if (!UsingUserBuffer) {
	    ExFreePoolWithTag(ScatterGatherBuffer, TAG_DMA);
	}
	return Status;
    }

    return STATUS_SUCCESS;
}

/**
 * @name HalpGetScatterGatherList
 *
 * Creates a scatter-gather list to be using in scatter/gather DMA
 *
 * @param DmaAdapter
 *        Adapter object representing the bus master or system dma controller.
 * @param DeviceObject
 *        The device target for DMA.
 * @param Mdl
 *        The MDL that describes the buffer to be mapped.
 * @param CurrentVa
 *        The current VA in the buffer to be mapped for transfer.
 * @param Length
 *        Specifies the length of data in bytes to be mapped.
 * @param ExecutionRoutine
 *        A caller supplied AdapterListControl routine to be called when DMA is available.
 * @param Context
 *        Context passed to the AdapterListControl routine.
 * @param WriteToDevice
 *        Indicates direction of DMA operation.
 *
 * @return The status of the operation.
 *
 * @see HalpBuildScatterGatherList
 *
 * @implemented
 */
NTAPI NTSTATUS HalpGetScatterGatherList(IN PDMA_ADAPTER DmaAdapter,
					IN PDEVICE_OBJECT DeviceObject,
					IN PMDL Mdl,
					IN PVOID CurrentVa,
					IN ULONG Length,
					IN PDRIVER_LIST_CONTROL ExecutionRoutine,
					IN PVOID Context,
					IN BOOLEAN WriteToDevice)
{
    return HalpBuildScatterGatherList(DmaAdapter, DeviceObject, Mdl, CurrentVa, Length,
				      ExecutionRoutine, Context, WriteToDevice, NULL, 0);
}

/**
 * @name HalpPutScatterGatherList
 *
 * Frees a scatter-gather list allocated from HalpBuildScatterGatherList
 *
 * @param DmaAdapter
 *        Adapter object representing the bus master or system dma controller.
 * @param ScatterGather
 *        The scatter/gather list to be freed.
 * @param WriteToDevice
 *        Indicates direction of DMA operation.
 *
 * @return None
 *
 * @see HalpBuildScatterGatherList
 *
 * @implemented
 */
NTAPI VOID HalpPutScatterGatherList(IN PDMA_ADAPTER DmaAdapter,
				    IN PSCATTER_GATHER_LIST ScatterGather,
				    IN BOOLEAN WriteToDevice)
{
    PSCATTER_GATHER_CONTEXT AdapterControlContext = (PSCATTER_GATHER_CONTEXT)ScatterGather->Reserved;

    for (ULONG i = 0; i < ScatterGather->NumberOfElements; i++) {
	HalpFlushAdapterBuffers(DmaAdapter,
				AdapterControlContext->Mdl,
				AdapterControlContext->MapRegisterBase,
				AdapterControlContext->CurrentVa,
				ScatterGather->Elements[i].Length,
				AdapterControlContext->WriteToDevice);
	AdapterControlContext->CurrentVa += ScatterGather->Elements[i].Length;
    }

    HalpFreeMapRegisters(DmaAdapter,
			 AdapterControlContext->MapRegisterBase,
			 AdapterControlContext->MapRegisterCount);

    ExFreePoolWithTag(ScatterGather, TAG_DMA);

    /* If this is our buffer, release it */
    if (!AdapterControlContext->UsingUserBuffer)
	ExFreePoolWithTag(AdapterControlContext, TAG_DMA);

    DPRINT("S/G DMA has finished!\n");
}

static DMA_OPERATIONS HalpDmaOperations = {
    .Size = sizeof(DMA_OPERATIONS),
    .PutDmaAdapter = HalpPutDmaAdapter,
    .AllocateCommonBuffer = HalpAllocateCommonBuffer,
    .FreeCommonBuffer = HalpFreeCommonBuffer,
    .AllocateAdapterChannel = HalpAllocateAdapterChannel,
    .FlushAdapterBuffers = HalpFlushAdapterBuffers,
    .FreeAdapterChannel = HalpFreeAdapterChannel,
    .FreeMapRegisters = HalpFreeMapRegisters,
    .MapTransfer = HalpMapTransfer,
    .GetDmaAlignment = HalpDmaGetDmaAlignment,
    .ReadDmaCounter = HalpReadDmaCounter,
    .GetScatterGatherList = HalpGetScatterGatherList,
    .PutScatterGatherList = HalpPutScatterGatherList,
    .CalculateScatterGatherList = HalpCalculateScatterGatherListSize,
    .BuildScatterGatherList = HalpBuildScatterGatherList,
};
