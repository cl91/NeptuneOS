#pragma once

#include <ntdef.h>
#include <ntioapi.h>
#include <hal.h>

/*
 * DMA Mode Registers 0x0B and 0xD6 (Write)
 *
 * MSB                             LSB
 *    x   x   x   x     x   x   x   x
 *    \---/   -   -     -----   -----
 *      |     |   |       |       |     00 - Channel 0 select
 *      |     |   |       |       \---- 01 - Channel 1 select
 *      |     |   |       |             10 - Channel 2 select
 *      |     |   |       |             11 - Channel 3 select
 *      |     |   |       |
 *      |     |   |       |             00 - Verify transfer
 *      |     |   |       \------------ 01 - Write transfer
 *      |     |   |                     10 - Read transfer
 *      |     |   |
 *      |     |   \--------------------  0 - Autoinitialized
 *      |     |                          1 - Non-autoinitialized
 *      |     |
 *      |     \------------------------  0 - Address increment select
 *      |
 *      |                               00 - Demand mode
 *      \------------------------------ 01 - Single mode
 *                                      10 - Block mode
 *                                      11 - Cascade mode
 */
typedef union _DMA_MODE {
    struct {
	UCHAR Channel:2;
	UCHAR TransferType:2;
	UCHAR AutoInitialize:1;
	UCHAR AddressDecrement:1;
	UCHAR RequestMode:2;
    };
    UCHAR Byte;
} DMA_MODE, *PDMA_MODE;

/* Transfer Types */
#define VERIFY_TRANSFER 0x00
#define READ_TRANSFER   0x01
#define WRITE_TRANSFER  0x02

/* Request Modes */
#define DEMAND_REQUEST_MODE  0x00
#define SINGLE_REQUEST_MODE  0x01
#define BLOCK_REQUEST_MODE   0x02
#define CASCADE_REQUEST_MODE 0x03

/*
 * Map register object. A map register object is a contiguous range of 4K
 * pages in the physical memory that are used as intermediate buffers for
 * DMA devices/controllers that cannot access the full physical address space.
 */
typedef struct _MAP_REGISTER_ENTRY {
    LIST_ENTRY Link;	/* List entry for MAP_REGISTER_CONTROL.List */
    LIST_ENTRY AdapterLink; /* List entry for ADAPTER_OBJECT.MapRegisterList */
    struct _ADAPTER_OBJECT *AssignedAdapter; /* If empty, map reg is free. */
    PVOID VirtBase; /* Virtual address in driver process of the first page */
    PHYSICAL_ADDRESS PhyBase;	/* Physical address of the first page */
    ULONG Count; /* Number of 4KB pages in this map register entry. */
    BOOLEAN Keep; /* TRUE if driver wants to release adapter but keep map reg */
} MAP_REGISTER_ENTRY, *PMAP_REGISTER_ENTRY;

/*
 * Map register control object. This is the singleton factory object for
 * all map registers of this driver process.
 */
typedef struct _MAP_REGISTER_CONTROL {
    LIST_ENTRY List; /* List of all map registers. The 24-bit ones are prepended
		      * to the list, and the 32-bit ones are appended to the list. */
} MAP_REGISTER_CONTROL, *PMAP_REGISTER_CONTROL;

/*
 * System (E)ISA DMA controller object. On a PC system, there are a total of seven of
 * these, corresponding to the first eight DMA channels except channel 4. Since the
 * system (E)ISA DMA controller can only be accessed by one driver at a time, client
 * drivers obtain a HANDLE to a server-side object corresponding to the DMA channel
 * to synchronize access to the system DMA controller.
 */
typedef struct _SYSTEM_DMA_ADAPTER {
    HANDLE Handle; /* Handle to the server side system controller object. */
    DMA_MODE AdapterMode;
    BOOLEAN Width16Bits;
} SYSTEM_DMA_ADAPTER, *PSYSTEM_DMA_ADAPTER;

/*
 * Adapter object
 */
typedef struct _ADAPTER_OBJECT {
    /*
     * New style DMA object definition. The fact that it is at the beginning
     * of the ADAPTER_OBJECT structure allows us to easily implement the
     * fallback implementation of IoGetDmaAdapter.
     */
    DMA_ADAPTER DmaHeader;

    /* We keep track of all DMA adapters of this driver process in a list */
    LIST_ENTRY Link;

    /* List of the map registers allocated for this adapter. */
    LIST_ENTRY MapRegisterList;

    /* If the adapter is a slave DMA adapter (ie. DMA using the system ISA
     * DMA controller), this points to the system DMA adapter object. */
    PSYSTEM_DMA_ADAPTER SystemAdapter;

    /* Maximum number of map registers the device can allocate for a DMA transfer. */
    ULONG MaxMapRegs;

    /* For bus master devices, this field signifies that the hardware supports
     * transfer of data to and from noncontiguous ranges of physical memory.
     * For slave devices, this field indicates that the device can be paused
     * between page transfers, allowing the I/O Manager to repoint the DMA
     * channel's address register to a new page of physical memory. */
    BOOLEAN ScatterGather;

    /* Specifies whether the device can use full 64-bit addresses for its DMA
     * operations. If FALSE, bus master devices (ie. non-ISA devices) will be
     * 32-bit only, and ISA devices will be 24-bit only. */
    BOOLEAN Dma64BitAddresses;

    /* If a particular DMA transfer needs map registers, HalpMapTransfer will
     * set this member to TRUE so later HalpFlushCommonBuffer knows to flush data
     * in the map registers. Note that this depends on the MDL and transfer length
     * and therefore may change every time HalpMapTransfer is called. */
    BOOLEAN UseMapRegisters;
} ADAPTER_OBJECT, *PADAPTER_OBJECT;
