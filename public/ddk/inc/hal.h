#pragma once

#include <ntddk.h>
#include <memaccess.h>
#include <ntdddisk.h>

#if defined(_M_IX86) || defined(_M_AMD64)
/*
 * X86 Port routines
 */
__cdecl NTSYSAPI UCHAR __inbyte(IN USHORT PortNum);
__cdecl NTSYSAPI VOID __outbyte(IN USHORT PortNum,
				IN UCHAR Data);
__cdecl NTSYSAPI USHORT __inword(IN USHORT PortNum);
__cdecl NTSYSAPI VOID __outword(IN USHORT PortNum,
				IN USHORT Data);
__cdecl NTSYSAPI ULONG __indword(IN USHORT PortNum);
__cdecl NTSYSAPI VOID __outdword(IN USHORT PortNum,
				 IN ULONG Data);

__cdecl NTSYSAPI VOID __inbytestring(IN USHORT PortNum,
				     OUT PUCHAR Data,
				     IN ULONG Count);
__cdecl NTSYSAPI VOID __outbytestring(IN USHORT PortNum,
				      IN PUCHAR Data,
				      IN ULONG Count);
__cdecl NTSYSAPI VOID __inwordstring(IN USHORT PortNum,
				     OUT PUSHORT Data,
				     IN ULONG Count);
__cdecl NTSYSAPI VOID __outwordstring(IN USHORT PortNum,
				      IN PUSHORT Data,
				      IN ULONG Count);
__cdecl NTSYSAPI VOID __indwordstring(IN USHORT PortNum,
				      OUT PULONG Data,
				      IN ULONG Count);
__cdecl NTSYSAPI VOID __outdwordstring(IN USHORT PortNum,
				       IN PULONG Data,
				       IN ULONG Count);

#define READ_PORT_UCHAR(Port)		__inbyte((ULONG_PTR)(Port))
#define WRITE_PORT_UCHAR(Port, Data)	__outbyte((ULONG_PTR)(Port), Data)
#define READ_PORT_USHORT(Port)		__inword((ULONG_PTR)(Port))
#define WRITE_PORT_USHORT(Port, Data)	__outword((ULONG_PTR)(Port), Data)
#define READ_PORT_ULONG(Port)		__indword((ULONG_PTR)(Port))
#define WRITE_PORT_ULONG(Port, Data)	__outdword((ULONG_PTR)(Port), Data)

#define READ_PORT_BUFFER_UCHAR(Port, Buffer, Count)		\
    __inbytestring((USHORT)(ULONG_PTR)Port, Buffer, Count)
#define READ_PORT_BUFFER_USHORT(Port, Buffer, Count)		\
    __inwordstring((USHORT)(ULONG_PTR)Port, Buffer, Count)
#define READ_PORT_BUFFER_ULONG(Port, Buffer, Count)		\
    __indwordstring((USHORT)(ULONG_PTR)Port, Buffer, Count)
#define WRITE_PORT_BUFFER_UCHAR(Port, Buffer, Count)		\
    __outbytestring((USHORT)(ULONG_PTR)Port, Buffer, Count)
#define WRITE_PORT_BUFFER_USHORT(Port, Buffer, Count)		\
    __outwordstring((USHORT)(ULONG_PTR)Port, Buffer, Count)
#define WRITE_PORT_BUFFER_ULONG(Port, Buffer, Count)		\
    __outdwordstring((USHORT)(ULONG_PTR)Port, Buffer, Count)

#else
#define READ_PORT_UCHAR(Port)		RtlRaiseStatus(STATUS_NOT_SUPPORTED)
#define WRITE_PORT_UCHAR(Port, Data)	RtlRaiseStatus(STATUS_NOT_SUPPORTED)
#define READ_PORT_USHORT(Port)		RtlRaiseStatus(STATUS_NOT_SUPPORTED)
#define WRITE_PORT_USHORT(Port, Data)	RtlRaiseStatus(STATUS_NOT_SUPPORTED)
#define READ_PORT_ULONG(Port)		RtlRaiseStatus(STATUS_NOT_SUPPORTED)
#define WRITE_PORT_ULONG(Port, Data)	RtlRaiseStatus(STATUS_NOT_SUPPORTED)
#endif

NTAPI NTSYSAPI NTSTATUS IoEnablePort(IN USHORT PortNum,
				     IN USHORT Len);

/*
 * The READ/WRITE_REGISTER_Xxx macros need compiler and memory barriers.
 */
#define READ_REGISTER_UCHAR(x) \
    (MemoryBarrier(), *(volatile UCHAR * const)(x))

#define READ_REGISTER_USHORT(x) \
    (MemoryBarrier(), *(volatile USHORT * const)(x))

#define READ_REGISTER_ULONG(x) \
    (MemoryBarrier(), *(volatile ULONG * const)(x))

#define READ_REGISTER_ULONG64(x) \
    (MemoryBarrier(), *(volatile ULONG64 * const)(x))

#define READ_REGISTER_BUFFER_UCHAR(x, y, z) {                           \
    PUCHAR registerBuffer = x;                                          \
    PUCHAR readBuffer = y;                                              \
    ULONG readCount;                                                    \
    MemoryBarrier();                                                    \
    for (readCount = z; readCount--; readBuffer++, registerBuffer++) {  \
        *readBuffer = *(volatile UCHAR * const)(registerBuffer);        \
    }                                                                   \
}

#define READ_REGISTER_BUFFER_USHORT(x, y, z) {                          \
    PUSHORT registerBuffer = x;                                         \
    PUSHORT readBuffer = y;                                             \
    ULONG readCount;                                                    \
    MemoryBarrier();                                                    \
    for (readCount = z; readCount--; readBuffer++, registerBuffer++) {  \
        *readBuffer = *(volatile USHORT * const)(registerBuffer);       \
    }                                                                   \
}

#define READ_REGISTER_BUFFER_ULONG(x, y, z) {                           \
    PULONG registerBuffer = x;                                          \
    PULONG readBuffer = y;                                              \
    ULONG readCount;                                                    \
    MemoryBarrier();                                                    \
    for (readCount = z; readCount--; readBuffer++, registerBuffer++) {  \
        *readBuffer = *(volatile ULONG * const)(registerBuffer);        \
    }                                                                   \
}

#define READ_REGISTER_BUFFER_ULONG64(x, y, z) {                         \
    PULONG64 registerBuffer = x;                                        \
    PULONG64 readBuffer = y;                                            \
    ULONG readCount;                                                    \
    MemoryBarrier();                                                    \
    for (readCount = z; readCount--; readBuffer++, registerBuffer++) {  \
        *readBuffer = *(volatile ULONG64 * const)(registerBuffer);      \
    }                                                                   \
}

#define WRITE_REGISTER_UCHAR(x, y) {    \
    *(volatile UCHAR * const)(x) = y;   \
    MemoryBarrier();                    \
}

#define WRITE_REGISTER_USHORT(x, y) {   \
    *(volatile USHORT * const)(x) = y;  \
    MemoryBarrier();               \
}

#define WRITE_REGISTER_ULONG(x, y) {    \
    *(volatile ULONG * const)(x) = y;   \
    MemoryBarrier();                    \
}

#define WRITE_REGISTER_ULONG64(x, y) {  \
    *(volatile ULONG64 * const)(x) = y; \
    MemoryBarrier();                    \
}

#define WRITE_REGISTER_BUFFER_UCHAR(x, y, z) {                            \
    PUCHAR registerBuffer = x;                                            \
    PUCHAR writeBuffer = y;                                               \
    ULONG writeCount;                                                     \
    for (writeCount = z; writeCount--; writeBuffer++, registerBuffer++) { \
        *(volatile UCHAR * const)(registerBuffer) = *writeBuffer;         \
    }                                                                     \
    MemoryBarrier();                                                      \
}

#define WRITE_REGISTER_BUFFER_USHORT(x, y, z) {                           \
    PUSHORT registerBuffer = x;                                           \
    PUSHORT writeBuffer = y;                                              \
    ULONG writeCount;                                                     \
    for (writeCount = z; writeCount--; writeBuffer++, registerBuffer++) { \
        *(volatile USHORT * const)(registerBuffer) = *writeBuffer;        \
    }                                                                     \
    MemoryBarrier();                                                      \
}

#define WRITE_REGISTER_BUFFER_ULONG(x, y, z) {                            \
    PULONG registerBuffer = x;                                            \
    PULONG writeBuffer = y;                                               \
    ULONG writeCount;                                                     \
    for (writeCount = z; writeCount--; writeBuffer++, registerBuffer++) { \
        *(volatile ULONG * const)(registerBuffer) = *writeBuffer;         \
    }                                                                     \
    MemoryBarrier();                                                      \
}

#define WRITE_REGISTER_BUFFER_ULONG64(x, y, z) {                          \
    PULONG64 registerBuffer = x;                                          \
    PULONG64 writeBuffer = y;                                             \
    ULONG writeCount;                                                     \
    for (writeCount = z; writeCount--; writeBuffer++, registerBuffer++) { \
        *(volatile ULONG64 * const)(registerBuffer) = *writeBuffer;       \
    }                                                                     \
    MemoryBarrier();                                                      \
}


/*
 * DMA data types and routines
 */

typedef enum _DMA_WIDTH {
    Width8Bits,
    Width16Bits,
    Width32Bits,
    MaximumDmaWidth
} DMA_WIDTH, *PDMA_WIDTH;

typedef enum _DMA_SPEED {
    Compatible,
    TypeA,
    TypeB,
    TypeC,
    TypeF,
    MaximumDmaSpeed
} DMA_SPEED, *PDMA_SPEED;

typedef struct _SCATTER_GATHER_ELEMENT {
    PHYSICAL_ADDRESS Address;
    ULONG Length;
    ULONG_PTR Reserved;
} SCATTER_GATHER_ELEMENT, *PSCATTER_GATHER_ELEMENT;

typedef struct _SCATTER_GATHER_LIST {
    ULONG NumberOfElements;
    ULONG_PTR Reserved;
    SCATTER_GATHER_ELEMENT Elements[1];
} SCATTER_GATHER_LIST, *PSCATTER_GATHER_LIST;

typedef enum _IO_ALLOCATION_ACTION {
    KeepObject = 1,
    DeallocateObject,
    DeallocateObjectKeepRegisters
} IO_ALLOCATION_ACTION, *PIO_ALLOCATION_ACTION;

typedef ULONG NODE_REQUIREMENT;

/* Valid values for NOTE_REQUIREMENT */
#define MM_DONT_ZERO_ALLOCATION                  0x00000001
#define MM_ALLOCATE_FROM_LOCAL_NODE_ONLY         0x00000002
#define MM_ALLOCATE_FULLY_REQUIRED               0x00000004
#define MM_ALLOCATE_NO_WAIT                      0x00000008
#define MM_ALLOCATE_PREFER_CONTIGUOUS            0x00000010
#define MM_ALLOCATE_REQUIRE_CONTIGUOUS_CHUNKS    0x00000020
#define MM_ANY_NODE_OK                           0x80000000

/* DEVICE_DESCRIPTION.Version */

#define DEVICE_DESCRIPTION_VERSION        0x0000
#define DEVICE_DESCRIPTION_VERSION1       0x0001
#define DEVICE_DESCRIPTION_VERSION2       0x0002
#define DEVICE_DESCRIPTION_VERSION3       0x0003

typedef struct _DEVICE_DESCRIPTION {
    ULONG Version;
    BOOLEAN Master;
    BOOLEAN ScatterGather;
    BOOLEAN DemandMode;
    BOOLEAN AutoInitialize;
    BOOLEAN Dma32BitAddresses;
    BOOLEAN IgnoreCount;
    BOOLEAN Reserved1;
    BOOLEAN Dma64BitAddresses;
    ULONG BusNumber;
    ULONG DmaChannel;
    INTERFACE_TYPE InterfaceType;
    DMA_WIDTH DmaWidth;
    DMA_SPEED DmaSpeed;
    ULONG MaximumLength;
    ULONG DmaPort;
#if (NTDDI_VERSION >= NTDDI_WIN8)
    ULONG DmaAddressWidth;
    ULONG DmaControllerInstance;
    ULONG DmaRequestLine;
    PHYSICAL_ADDRESS DeviceAddress;
#endif				// NTDDI_WIN8
} DEVICE_DESCRIPTION, *PDEVICE_DESCRIPTION;

#define DMA_ADAPTER_INFO_VERSION1   1

#define ADAPTER_INFO_SYNCHRONOUS_CALLBACK             0x0001
#define ADAPTER_INFO_API_BYPASS                       0x0002

typedef struct _DMA_ADAPTER_INFO_V1 {
    ULONG ReadDmaCounterAvailable;
    ULONG ScatterGatherLimit;
    ULONG DmaAddressWidth;
    ULONG Flags;
    ULONG MinimumTransferUnit;
} DMA_ADAPTER_INFO_V1, *PDMA_ADAPTER_INFO_V1;

typedef struct _DMA_ADAPTER_INFO {
    ULONG Version;
    union {
	DMA_ADAPTER_INFO_V1 V1;
    };
} DMA_ADAPTER_INFO, *PDMA_ADAPTER_INFO;

#define DMA_TRANSFER_INFO_VERSION1  1
#define DMA_TRANSFER_INFO_VERSION2  2

typedef struct _DMA_TRANSFER_INFO_V1 {
    ULONG MapRegisterCount;
    ULONG ScatterGatherElementCount;
    ULONG ScatterGatherListSize;
} DMA_TRANSFER_INFO_V1, *PDMA_TRANSFER_INFO_V1;

typedef struct _DMA_TRANSFER_INFO_V2 {
    ULONG MapRegisterCount;
    ULONG ScatterGatherElementCount;
    ULONG ScatterGatherListSize;
    ULONG LogicalPageCount;
} DMA_TRANSFER_INFO_V2, *PDMA_TRANSFER_INFO_V2;

typedef struct _DMA_TRANSFER_INFO {
    ULONG Version;
    union {
	DMA_TRANSFER_INFO_V1 V1;
	DMA_TRANSFER_INFO_V2 V2;
    };
} DMA_TRANSFER_INFO, *PDMA_TRANSFER_INFO;

#define DMA_TRANSFER_CONTEXT_VERSION1 1

#ifdef _WIN64
#define DMA_TRANSFER_CONTEXT_SIZE_V1 128
#else
#define DMA_TRANSFER_CONTEXT_SIZE_V1 64
#endif

typedef struct _DMA_ADAPTER {
    USHORT Version;
    USHORT Size;
    struct _DMA_OPERATIONS *DmaOperations;
} DMA_ADAPTER, *PDMA_ADAPTER;

typedef enum {
    DmaComplete,
    DmaAborted,
    DmaError,
    DmaCancelled
} DMA_COMPLETION_STATUS;

typedef VOID (NTAPI *PPUT_DMA_ADAPTER)(PDMA_ADAPTER DmaAdapter);

typedef PVOID (NTAPI *PALLOCATE_COMMON_BUFFER)(IN PDMA_ADAPTER DmaAdapter,
					       IN ULONG Length,
					       OUT PPHYSICAL_ADDRESS LogicalAddress,
					       IN BOOLEAN CacheEnabled);

typedef VOID (NTAPI *PFREE_COMMON_BUFFER)(IN PDMA_ADAPTER DmaAdapter,
					  IN ULONG Length,
					  IN PHYSICAL_ADDRESS LogicalAddress,
					  IN PVOID VirtualAddress,
					  IN BOOLEAN CacheEnabled);

typedef IO_ALLOCATION_ACTION (NTAPI DRIVER_CONTROL)(IN PDEVICE_OBJECT DeviceObject,
						    IN PVOID MapRegisterBase,
						    IN PVOID Context);
typedef DRIVER_CONTROL *PDRIVER_CONTROL;

typedef NTSTATUS (NTAPI *PALLOCATE_ADAPTER_CHANNEL)(IN PDMA_ADAPTER DmaAdapter,
						    IN PDEVICE_OBJECT DeviceObject,
						    IN ULONG NumberOfMapRegisters,
						    IN PDRIVER_CONTROL ExecutionRoutine,
						    IN PVOID Context);

typedef BOOLEAN (NTAPI *PFLUSH_ADAPTER_BUFFERS)(IN PDMA_ADAPTER DmaAdapter,
						IN PMDL Mdl,
						IN PVOID MapRegisterBase,
						IN PVOID CurrentVa,
						IN ULONG Length,
						IN BOOLEAN WriteToDevice);

typedef VOID (NTAPI *PFREE_ADAPTER_CHANNEL)(IN PDMA_ADAPTER DmaAdapter);

typedef VOID (NTAPI *PFREE_MAP_REGISTERS)(IN PDMA_ADAPTER DmaAdapter,
					  PVOID MapRegisterBase,
					  ULONG NumberOfMapRegisters);

typedef PHYSICAL_ADDRESS (NTAPI *PMAP_TRANSFER)(IN PDMA_ADAPTER DmaAdapter,
						IN PMDL Mdl,
						IN PVOID MapRegisterBase,
						IN PVOID CurrentVa,
						IN OUT PULONG Length,
						IN BOOLEAN WriteToDevice);

typedef ULONG (NTAPI *PGET_DMA_ALIGNMENT)(IN PDMA_ADAPTER DmaAdapter);

typedef ULONG (NTAPI *PREAD_DMA_COUNTER)(IN PDMA_ADAPTER DmaAdapter);

typedef VOID (NTAPI DRIVER_LIST_CONTROL)(IN PDEVICE_OBJECT DeviceObject,
					 IN PSCATTER_GATHER_LIST ScatterGather,
					 IN PVOID Context);
typedef DRIVER_LIST_CONTROL *PDRIVER_LIST_CONTROL;

typedef NTSTATUS (NTAPI *PGET_SCATTER_GATHER_LIST)(IN PDMA_ADAPTER DmaAdapter,
						   IN PDEVICE_OBJECT DeviceObject,
						   IN PMDL Mdl,
						   IN PVOID CurrentVa,
						   IN ULONG Length,
						   IN PDRIVER_LIST_CONTROL ExecutionRoutine,
						   IN PVOID Context,
						   IN BOOLEAN WriteToDevice);

typedef VOID (NTAPI *PPUT_SCATTER_GATHER_LIST)(IN PDMA_ADAPTER DmaAdapter,
					       IN PSCATTER_GATHER_LIST ScatterGather,
					       IN BOOLEAN WriteToDevice);

typedef NTSTATUS (NTAPI *PCALCULATE_SCATTER_GATHER_LIST_SIZE)(IN PDMA_ADAPTER DmaAdapter,
							      IN PMDL Mdl OPTIONAL,
							      IN PVOID CurrentVa,
							      IN ULONG Length,
							      OUT PULONG ScatterGatherListSize,
							      OUT OPTIONAL PULONG pNumberOfMapRegisters);

typedef NTSTATUS (NTAPI *PBUILD_SCATTER_GATHER_LIST)(IN PDMA_ADAPTER DmaAdapter,
						     IN PDEVICE_OBJECT DeviceObject,
						     IN PMDL Mdl,
						     IN PVOID CurrentVa,
						     IN ULONG Length,
						     IN PDRIVER_LIST_CONTROL ExecutionRoutine,
						     IN PVOID Context,
						     IN BOOLEAN WriteToDevice,
						     IN PVOID ScatterGatherBuffer,
						     IN ULONG ScatterGatherLength);

typedef NTSTATUS (NTAPI *PBUILD_MDL_FROM_SCATTER_GATHER_LIST)(IN PDMA_ADAPTER DmaAdapter,
							      IN PSCATTER_GATHER_LIST ScatterGather,
							      IN PMDL OriginalMdl,
							      OUT PMDL *TargetMdl);

typedef NTSTATUS (NTAPI *PGET_DMA_ADAPTER_INFO)(IN PDMA_ADAPTER DmaAdapter,
						IN OUT PDMA_ADAPTER_INFO AdapterInfo);

typedef NTSTATUS (NTAPI *PGET_DMA_TRANSFER_INFO)(IN PDMA_ADAPTER DmaAdapter,
						 IN PMDL Mdl,
						 IN ULONGLONG Offset,
						 IN ULONG Length,
						 IN BOOLEAN WriteOnly,
						 IN OUT PDMA_TRANSFER_INFO TransferInfo);

typedef NTSTATUS (NTAPI *PINITIALIZE_DMA_TRANSFER_CONTEXT)(IN PDMA_ADAPTER DmaAdapter,
							   OUT PVOID DmaTransferContext);

typedef PVOID (NTAPI *PALLOCATE_COMMON_BUFFER_EX)(IN PDMA_ADAPTER DmaAdapter,
						  IN OPTIONAL PPHYSICAL_ADDRESS MaximumAddress,
						  IN ULONG Length,
						  OUT PPHYSICAL_ADDRESS LogicalAddress,
						  IN BOOLEAN CacheEnabled,
						  IN NODE_REQUIREMENT PreferredNode);

typedef NTSTATUS (NTAPI *PALLOCATE_ADAPTER_CHANNEL_EX)(IN PDMA_ADAPTER DmaAdapter,
						       IN PDEVICE_OBJECT DeviceObject,
						       IN PVOID DmaTransferContext,
						       IN ULONG NumberOfMapRegisters,
						       IN ULONG Flags,
						       IN OPTIONAL PDRIVER_CONTROL ExecutionRoutine,
						       IN OPTIONAL PVOID ExecutionContext,
						       OUT OPTIONAL PVOID *MapRegisterBase);

typedef NTSTATUS (NTAPI *PCONFIGURE_ADAPTER_CHANNEL)(IN PDMA_ADAPTER DmaAdapter,
						     IN ULONG FunctionNumber,
						     IN PVOID Context);

typedef BOOLEAN (NTAPI *PCANCEL_ADAPTER_CHANNEL)(IN PDMA_ADAPTER DmaAdapter,
						 IN PDEVICE_OBJECT DeviceObject,
						 IN PVOID DmaTransferContext);

typedef VOID NTAPI DMA_COMPLETION_ROUTINE(IN PDMA_ADAPTER DmaAdapter,
					  IN PDEVICE_OBJECT DeviceObject,
					  IN PVOID CompletionContext,
					  IN DMA_COMPLETION_STATUS Status);

typedef DMA_COMPLETION_ROUTINE *PDMA_COMPLETION_ROUTINE;

typedef NTSTATUS (NTAPI *PMAP_TRANSFER_EX)(IN PDMA_ADAPTER DmaAdapter,
					   IN PMDL Mdl,
					   IN PVOID MapRegisterBase,
					   IN ULONGLONG Offset,
					   IN ULONG DeviceOffset,
					   IN OUT PULONG Length,
					   IN BOOLEAN WriteToDevice,
					   OUT PSCATTER_GATHER_LIST ScatterGatherBuffer,
					   IN ULONG ScatterGatherBufferLength,
					   IN OPTIONAL PDMA_COMPLETION_ROUTINE DmaCompletionRoutine,
					   IN OPTIONAL PVOID CompletionContext);

typedef NTSTATUS (NTAPI *PGET_SCATTER_GATHER_LIST_EX)(IN PDMA_ADAPTER DmaAdapter,
						      IN PDEVICE_OBJECT DeviceObject,
						      IN PVOID DmaTransferContext,
						      IN PMDL Mdl,
						      IN ULONGLONG Offset,
						      IN ULONG Length,
						      IN ULONG Flags,
						      IN OPTIONAL PDRIVER_LIST_CONTROL ExecutionRoutine,
						      IN OPTIONAL PVOID Context,
						      IN BOOLEAN WriteToDevice,
						      IN OPTIONAL PDMA_COMPLETION_ROUTINE DmaCompletionRoutine,
						      IN OPTIONAL PVOID CompletionContext,
						      OUT OPTIONAL PSCATTER_GATHER_LIST *ScatterGatherList);

typedef NTSTATUS (NTAPI *PBUILD_SCATTER_GATHER_LIST_EX)(IN PDMA_ADAPTER DmaAdapter,
							IN PDEVICE_OBJECT DeviceObject,
							IN PVOID DmaTransferContext,
							IN PMDL Mdl,
							IN ULONGLONG Offset,
							IN ULONG Length,
							IN ULONG Flags,
							IN OPTIONAL PDRIVER_LIST_CONTROL ExecutionRoutine,
							IN OPTIONAL PVOID Context,
							IN BOOLEAN WriteToDevice,
							IN PVOID ScatterGatherBuffer,
							IN ULONG ScatterGatherLength,
							IN OPTIONAL PDMA_COMPLETION_ROUTINE DmaCompletionRoutine,
							IN OPTIONAL PVOID CompletionContext,
							OUT OPTIONAL PVOID ScatterGatherList);

typedef NTSTATUS (NTAPI *PFLUSH_ADAPTER_BUFFERS_EX)(IN PDMA_ADAPTER DmaAdapter,
						    IN PMDL Mdl,
						    IN PVOID MapRegisterBase,
						    IN ULONGLONG Offset,
						    IN ULONG Length,
						    IN BOOLEAN WriteToDevice);

typedef VOID (NTAPI *PFREE_ADAPTER_OBJECT)(IN PDMA_ADAPTER DmaAdapter,
					   IN IO_ALLOCATION_ACTION AllocationAction);

typedef NTSTATUS (NTAPI *PCANCEL_MAPPED_TRANSFER)(IN PDMA_ADAPTER DmaAdapter,
						  IN PVOID DmaTransferContext);

typedef NTSTATUS (NTAPI *PALLOCATE_DOMAIN_COMMON_BUFFER)(IN PDMA_ADAPTER DmaAdapter,
							 IN HANDLE DomainHandle,
							 IN OPTIONAL PPHYSICAL_ADDRESS MaximumAddress,
							 IN ULONG Length,
							 IN ULONG Flags,
							 IN OPTIONAL MEMORY_CACHING_TYPE *CacheType,
							 IN NODE_REQUIREMENT PreferredNode,
							 OUT PPHYSICAL_ADDRESS LogicalAddress,
							 OUT PVOID *VirtualAddress);

typedef NTSTATUS (NTAPI *PFLUSH_DMA_BUFFER)(IN PDMA_ADAPTER DmaAdapter,
					    IN PMDL Mdl,
					    IN BOOLEAN ReadOperation);

typedef NTSTATUS (NTAPI *PJOIN_DMA_DOMAIN)(IN PDMA_ADAPTER DmaAdapter,
					   IN HANDLE DomainHandle);

typedef NTSTATUS (NTAPI *PLEAVE_DMA_DOMAIN)(IN PDMA_ADAPTER DmaAdapter);

typedef HANDLE (NTAPI *PGET_DMA_DOMAIN)(IN PDMA_ADAPTER DmaAdapter);

typedef PVOID (NTAPI *PALLOCATE_COMMON_BUFFER_WITH_BOUNDS)(IN PDMA_ADAPTER DmaAdapter,
							   IN OPTIONAL PPHYSICAL_ADDRESS MinimumAddress,
							   IN OPTIONAL PPHYSICAL_ADDRESS MaximumAddress,
							   IN ULONG Length,
							   IN ULONG Flags,
							   IN OPTIONAL MEMORY_CACHING_TYPE *CacheType,
							   IN NODE_REQUIREMENT PreferredNode,
							   OUT PPHYSICAL_ADDRESS LogicalAddress);

typedef struct _DMA_COMMON_BUFFER_VECTOR DMA_COMMON_BUFFER_VECTOR, *PDMA_COMMON_BUFFER_VECTOR;

typedef NTSTATUS (NTAPI *PALLOCATE_COMMON_BUFFER_VECTOR)(IN PDMA_ADAPTER DmaAdapter,
							 IN PHYSICAL_ADDRESS LowAddress,
							 IN PHYSICAL_ADDRESS HighAddress,
							 IN MEMORY_CACHING_TYPE CacheType,
							 IN ULONG IdealNode,
							 IN ULONG Flags,
							 IN ULONG NumberOfElements,
							 IN ULONGLONG SizeOfElements,
							 OUT PDMA_COMMON_BUFFER_VECTOR *VectorOut);

typedef VOID (NTAPI *PGET_COMMON_BUFFER_FROM_VECTOR_BY_INDEX)(IN PDMA_ADAPTER DmaAdapter,
							      IN PDMA_COMMON_BUFFER_VECTOR Vector,
							      IN ULONG Index,
							      OUT PVOID *VirtualAddressOut,
							      OUT PPHYSICAL_ADDRESS LogicalAddressOut);

typedef VOID (NTAPI *PFREE_COMMON_BUFFER_FROM_VECTOR)(IN PDMA_ADAPTER DmaAdapter,
						      IN PDMA_COMMON_BUFFER_VECTOR Vector,
						      IN ULONG Index);

typedef VOID (NTAPI *PFREE_COMMON_BUFFER_VECTOR)(IN PDMA_ADAPTER DmaAdapter,
						 IN PDMA_COMMON_BUFFER_VECTOR Vector);

typedef struct _DMA_OPERATIONS {
    ULONG Size;
    PPUT_DMA_ADAPTER PutDmaAdapter;
    PALLOCATE_COMMON_BUFFER AllocateCommonBuffer;
    PFREE_COMMON_BUFFER FreeCommonBuffer;
    PALLOCATE_ADAPTER_CHANNEL AllocateAdapterChannel;
    PFLUSH_ADAPTER_BUFFERS FlushAdapterBuffers;
    PFREE_ADAPTER_CHANNEL FreeAdapterChannel;
    PFREE_MAP_REGISTERS FreeMapRegisters;
    PMAP_TRANSFER MapTransfer;
    PGET_DMA_ALIGNMENT GetDmaAlignment;
    PREAD_DMA_COUNTER ReadDmaCounter;
    PGET_SCATTER_GATHER_LIST GetScatterGatherList;
    PPUT_SCATTER_GATHER_LIST PutScatterGatherList;
    PCALCULATE_SCATTER_GATHER_LIST_SIZE CalculateScatterGatherList;
    PBUILD_SCATTER_GATHER_LIST BuildScatterGatherList;
    PBUILD_MDL_FROM_SCATTER_GATHER_LIST BuildMdlFromScatterGatherList;
    PGET_DMA_ADAPTER_INFO GetDmaAdapterInfo;
    PGET_DMA_TRANSFER_INFO GetDmaTransferInfo;
    PINITIALIZE_DMA_TRANSFER_CONTEXT InitializeDmaTransferContext;
    PALLOCATE_COMMON_BUFFER_EX AllocateCommonBufferEx;
    PALLOCATE_ADAPTER_CHANNEL_EX AllocateAdapterChannelEx;
    PCONFIGURE_ADAPTER_CHANNEL ConfigureAdapterChannel;
    PCANCEL_ADAPTER_CHANNEL CancelAdapterChannel;
    PMAP_TRANSFER_EX MapTransferEx;
    PGET_SCATTER_GATHER_LIST_EX GetScatterGatherListEx;
    PBUILD_SCATTER_GATHER_LIST_EX BuildScatterGatherListEx;
    PFLUSH_ADAPTER_BUFFERS_EX FlushAdapterBuffersEx;
    PFREE_ADAPTER_OBJECT FreeAdapterObject;
    PCANCEL_MAPPED_TRANSFER CancelMappedTransfer;
    PALLOCATE_DOMAIN_COMMON_BUFFER AllocateDomainCommonBuffer;
    PFLUSH_DMA_BUFFER FlushDmaBuffer;
    PJOIN_DMA_DOMAIN JoinDmaDomain;
    PLEAVE_DMA_DOMAIN LeaveDmaDomain;
    PGET_DMA_DOMAIN GetDmaDomain;
    PALLOCATE_COMMON_BUFFER_WITH_BOUNDS AllocateCommonBufferWithBounds;
    PALLOCATE_COMMON_BUFFER_VECTOR AllocateCommonBufferVector;
    PGET_COMMON_BUFFER_FROM_VECTOR_BY_INDEX GetCommonBufferFromVectorByIndex;
    PFREE_COMMON_BUFFER_FROM_VECTOR FreeCommonBufferFromVector;
    PFREE_COMMON_BUFFER_VECTOR FreeCommonBufferVector;
} DMA_OPERATIONS, *PDMA_OPERATIONS;

FORCEINLINE NTAPI NTSTATUS IoAllocateAdapterChannel(IN PDMA_ADAPTER DmaAdapter,
						    IN PDEVICE_OBJECT DeviceObject,
						    IN ULONG NumberOfMapRegisters,
						    IN PDRIVER_CONTROL ExecutionRoutine,
						    IN PVOID Context)
{
    PALLOCATE_ADAPTER_CHANNEL AllocateAdapterChannel = DmaAdapter->DmaOperations->AllocateAdapterChannel;
    ASSERT(AllocateAdapterChannel);
    return AllocateAdapterChannel(DmaAdapter, DeviceObject, NumberOfMapRegisters, ExecutionRoutine, Context);
}

FORCEINLINE NTAPI BOOLEAN IoFlushAdapterBuffers(IN PDMA_ADAPTER DmaAdapter,
						IN PMDL Mdl,
						IN PVOID MapRegisterBase,
						IN PVOID CurrentVa,
						IN ULONG Length,
						IN BOOLEAN WriteToDevice)
{
    PFLUSH_ADAPTER_BUFFERS FlushAdapterBuffers = DmaAdapter->DmaOperations->FlushAdapterBuffers;
    ASSERT(FlushAdapterBuffers);
    return FlushAdapterBuffers(DmaAdapter, Mdl, MapRegisterBase, CurrentVa, Length, WriteToDevice);
}

FORCEINLINE NTAPI VOID IoFreeAdapterChannel(IN PDMA_ADAPTER DmaAdapter)
{
    PFREE_ADAPTER_CHANNEL FreeAdapterChannel = DmaAdapter->DmaOperations->FreeAdapterChannel;
    ASSERT(FreeAdapterChannel);
    FreeAdapterChannel(DmaAdapter);
}

FORCEINLINE NTAPI VOID IoFreeMapRegisters(IN PDMA_ADAPTER DmaAdapter,
					  IN PVOID MapRegisterBase,
					  IN ULONG NumberOfMapRegisters)
{
    PFREE_MAP_REGISTERS FreeMapRegisters = DmaAdapter->DmaOperations->FreeMapRegisters;
    ASSERT(FreeMapRegisters);
    FreeMapRegisters(DmaAdapter, MapRegisterBase, NumberOfMapRegisters);
}

FORCEINLINE NTAPI PHYSICAL_ADDRESS IoMapTransfer(IN PDMA_ADAPTER DmaAdapter,
						 IN PMDL Mdl,
						 IN PVOID MapRegisterBase,
						 IN PVOID CurrentVa,
						 IN OUT PULONG Length,
						 IN BOOLEAN WriteToDevice)
{
    PMAP_TRANSFER MapTransfer = DmaAdapter->DmaOperations->MapTransfer;
    ASSERT(MapTransfer);
    return MapTransfer(DmaAdapter, Mdl, MapRegisterBase, CurrentVa, Length, WriteToDevice);
}

/* Flush the memory region described by an MDL from caches of all processors.
 * On x86 and amd64 this is a NOOP because these architectures maintain cache
 * coherency without programmer's manual intervention. On RISC architectures
 * we need to manually flush cache lines. */
#if defined(_M_IX86) || defined(_M_AMD64)
FORCEINLINE NTAPI VOID KeFlushIoBuffers(IN PMDL Mdl,
					IN BOOLEAN ReadOperation,
					IN BOOLEAN DmaOperation)
{
    UNREFERENCED_PARAMETER(Mdl);
    UNREFERENCED_PARAMETER(ReadOperation);
    UNREFERENCED_PARAMETER(DmaOperation);
}
#else
NTAPI NTSYSAPI VOID KeFlushIoBuffers(IN PMDL Mdl,
				     IN BOOLEAN ReadOperation,
				     IN BOOLEAN DmaOperation);
#endif

FORCEINLINE NTAPI PVOID HalAllocateCommonBuffer(IN PDMA_ADAPTER DmaAdapter,
						IN ULONG Length,
						OUT PPHYSICAL_ADDRESS LogicalAddress,
						IN BOOLEAN CacheEnabled)
{
    PALLOCATE_COMMON_BUFFER AllocateCommonBuffer = DmaAdapter->DmaOperations->AllocateCommonBuffer;
    ASSERT(AllocateCommonBuffer != NULL);
    return AllocateCommonBuffer(DmaAdapter, Length, LogicalAddress, CacheEnabled);
}

FORCEINLINE NTAPI VOID HalFreeCommonBuffer(IN PDMA_ADAPTER DmaAdapter,
					   IN ULONG Length,
					   IN PHYSICAL_ADDRESS LogicalAddress,
					   IN PVOID VirtualAddress,
					   IN BOOLEAN CacheEnabled)
{
    PFREE_COMMON_BUFFER FreeCommonBuffer = DmaAdapter->DmaOperations->FreeCommonBuffer;
    ASSERT(FreeCommonBuffer != NULL);
    FreeCommonBuffer(DmaAdapter, Length, LogicalAddress, VirtualAddress, CacheEnabled);
}

FORCEINLINE NTAPI ULONG HalReadDmaCounter(IN PDMA_ADAPTER DmaAdapter)
{
    PREAD_DMA_COUNTER ReadDmaCounter = DmaAdapter->DmaOperations->ReadDmaCounter;
    ASSERT(ReadDmaCounter != NULL);
    return ReadDmaCounter(DmaAdapter);
}

FORCEINLINE NTAPI ULONG HalGetDmaAlignment(IN PDMA_ADAPTER DmaAdapter)
{
    PGET_DMA_ALIGNMENT GetDmaAlignment = DmaAdapter->DmaOperations->GetDmaAlignment;
    ASSERT(GetDmaAlignment != NULL);
    return GetDmaAlignment(DmaAdapter);
}

FORCEINLINE NTAPI NTSTATUS HalBuildScatterGatherList(IN PDMA_ADAPTER DmaAdapter,
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
    return DmaAdapter->DmaOperations->BuildScatterGatherList(DmaAdapter,
							     DeviceObject,
							     Mdl,
							     CurrentVa,
							     Length,
							     ExecutionRoutine,
							     Context,
							     WriteToDevice,
							     ScatterGatherBuffer,
							     ScatterGatherBufferLength);
}

FORCEINLINE NTAPI NTSTATUS HalGetScatterGatherList(IN PDMA_ADAPTER DmaAdapter,
						   IN PDEVICE_OBJECT DeviceObject,
						   IN PMDL Mdl,
						   IN PVOID CurrentVa,
						   IN ULONG Length,
						   IN PDRIVER_LIST_CONTROL ExecutionRoutine,
						   IN PVOID Context,
						   IN BOOLEAN WriteToDevice)
{
    return DmaAdapter->DmaOperations->GetScatterGatherList(DmaAdapter,
							   DeviceObject,
							   Mdl,
							   CurrentVa,
							   Length,
							   ExecutionRoutine,
							   Context,
							   WriteToDevice);
}

FORCEINLINE NTAPI VOID HalPutScatterGatherList(IN PDMA_ADAPTER DmaAdapter,
					       IN PSCATTER_GATHER_LIST ScatterGather,
					       IN BOOLEAN WriteToDevice)
{
    return DmaAdapter->DmaOperations->PutScatterGatherList(DmaAdapter,
							   ScatterGather,
							   WriteToDevice);
}

NTAPI NTSYSAPI PDMA_ADAPTER HalGetAdapter(IN PDEVICE_DESCRIPTION DeviceDescription,
					  OUT PULONG NumberOfMapRegisters);

NTAPI NTSYSAPI VOID HalPutDmaAdapter(IN PDMA_ADAPTER DmaAdapter);

/*
 * IO memory mapping routines
 */
NTAPI NTSYSAPI PVOID MmMapIoSpace(IN PHYSICAL_ADDRESS PhysicalAddress,
				  IN SIZE_T NumberOfBytes,
				  IN MEMORY_CACHING_TYPE CacheType);

NTAPI NTSYSAPI VOID MmUnmapIoSpace(IN PVOID BaseAddress,
				   IN SIZE_T NumberOfBytes);

NTAPI NTSYSAPI NTSTATUS MmAllocateContiguousMemorySpecifyCache(IN SIZE_T NumberOfBytes,
							       IN PHYSICAL_ADDRESS HighestAddr,
							       IN PHYSICAL_ADDRESS BoundaryAddr,
							       IN MEMORY_CACHING_TYPE CacheType,
							       OUT PVOID *VirtBase,
							       OUT PHYSICAL_ADDRESS *PhysBase);

NTAPI NTSYSAPI VOID MmFreeContiguousMemorySpecifyCache(IN PVOID BaseAddress,
						       IN SIZE_T NumberOfBytes,
						       IN MEMORY_CACHING_TYPE CacheType);

NTAPI NTSYSAPI PHYSICAL_ADDRESS MmGetPhysicalAddress(IN PVOID Address);

NTAPI NTSYSAPI PVOID MmGetVirtualForPhysical(IN PHYSICAL_ADDRESS PhysicalAddress);

/*
 * PC speaker access routine
 */
NTAPI NTSYSAPI BOOLEAN HalMakeBeep(IN ULONG Frequency);

/*
 * Returns the physical address and the length of the ACPI RSDT/XSDT
 */
NTSTATUS HalAcpiGetRsdt(OUT ULONG64 *Address,
			OUT ULONG *Length);

/*
 * Disk partition related routines
 */
NTAPI NTSYSAPI VOID HalExamineMBR(IN PDEVICE_OBJECT DeviceObject,
				  IN ULONG SectorSize,
				  IN ULONG MbrTypeIdentifier,
				  OUT PVOID *MbrBuffer);

NTAPI NTSYSAPI NTSTATUS IoReadPartitionTable(IN PDEVICE_OBJECT DeviceObject,
					     IN ULONG SectorSize,
					     IN BOOLEAN ReturnRecognizedPartitions,
					     IN OUT PDRIVE_LAYOUT_INFORMATION *PartitionBuffer);

NTAPI NTSTATUS IoReadPartitionTableEx(IN PDEVICE_OBJECT DeviceObject,
				      IN PDRIVE_LAYOUT_INFORMATION_EX *DriveLayout);

NTAPI NTSTATUS IoWritePartitionTable(IN PDEVICE_OBJECT DeviceObject,
				     IN ULONG SectorSize,
				     IN ULONG SectorsPerTrack,
				     IN ULONG NumberOfHeads,
				     IN PDRIVE_LAYOUT_INFORMATION PartitionBuffer);

NTAPI NTSTATUS IoWritePartitionTableEx(IN PDEVICE_OBJECT DeviceObject,
				       IN PDRIVE_LAYOUT_INFORMATION_EX DriveLayout);

NTAPI NTSTATUS IoSetPartitionInformation(IN PDEVICE_OBJECT DeviceObject,
					 IN ULONG SectorSize,
					 IN ULONG PartitionNumber,
					 IN ULONG PartitionType);

NTAPI NTSTATUS IoReadDiskSignature(IN PDEVICE_OBJECT DeviceObject,
				   IN ULONG BytesPerSector,
				   OUT PDISK_SIGNATURE Signature);
