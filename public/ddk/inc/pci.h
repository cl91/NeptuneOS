#pragma once

#include <nt.h>

/*
 * PCI/PCIE data types and routines
 */

typedef struct _PCI_SLOT_NUMBER {
    union {
	struct {
	    ULONG DeviceNumber:5;
	    ULONG FunctionNumber:3;
	    ULONG Reserved:24;
	} Bits;
	ULONG AsULONG;
    };
} PCI_SLOT_NUMBER, *PPCI_SLOT_NUMBER;

#define PCI_TYPE0_ADDRESSES               6
#define PCI_TYPE1_ADDRESSES               2
#define PCI_TYPE2_ADDRESSES               5

typedef struct _PCI_COMMON_HEADER {
    USHORT VendorID;
    USHORT DeviceID;
    USHORT Command;
    USHORT Status;
    UCHAR RevisionID;
    UCHAR ProgIf;
    UCHAR SubClass;
    UCHAR BaseClass;
    UCHAR CacheLineSize;
    UCHAR LatencyTimer;
    UCHAR HeaderType;
    UCHAR BIST;
    union {
	struct _PCI_HEADER_TYPE_0 {
	    ULONG BaseAddresses[PCI_TYPE0_ADDRESSES];
	    ULONG CIS;
	    USHORT SubVendorID;
	    USHORT SubSystemID;
	    ULONG ROMBaseAddress;
	    UCHAR CapabilitiesPtr;
	    UCHAR Reserved1[3];
	    ULONG Reserved2;
	    UCHAR InterruptLine;
	    UCHAR InterruptPin;
	    UCHAR MinimumGrant;
	    UCHAR MaximumLatency;
	} Type0;
	struct _PCI_HEADER_TYPE_1 {
	    ULONG BaseAddresses[PCI_TYPE1_ADDRESSES];
	    UCHAR PrimaryBus;
	    UCHAR SecondaryBus;
	    UCHAR SubordinateBus;
	    UCHAR SecondaryLatency;
	    UCHAR IOBase;
	    UCHAR IOLimit;
	    USHORT SecondaryStatus;
	    USHORT MemoryBase;
	    USHORT MemoryLimit;
	    USHORT PrefetchBase;
	    USHORT PrefetchLimit;
	    ULONG PrefetchBaseUpper32;
	    ULONG PrefetchLimitUpper32;
	    USHORT IOBaseUpper16;
	    USHORT IOLimitUpper16;
	    UCHAR CapabilitiesPtr;
	    UCHAR Reserved1[3];
	    ULONG ROMBaseAddress;
	    UCHAR InterruptLine;
	    UCHAR InterruptPin;
	    USHORT BridgeControl;
	} Type1;
	struct _PCI_HEADER_TYPE_2 {
	    ULONG SocketRegistersBaseAddress;
	    UCHAR CapabilitiesPtr;
	    UCHAR Reserved;
	    USHORT SecondaryStatus;
	    UCHAR PrimaryBus;
	    UCHAR SecondaryBus;
	    UCHAR SubordinateBus;
	    UCHAR SecondaryLatency;
	    struct {
		ULONG Base;
		ULONG Limit;
	    } Range[PCI_TYPE2_ADDRESSES-1];
	    UCHAR InterruptLine;
	    UCHAR InterruptPin;
	    USHORT BridgeControl;
	} Type2;
    };
} PCI_COMMON_HEADER, *PPCI_COMMON_HEADER;

typedef struct _PCI_COMMON_CONFIG {
    PCI_COMMON_HEADER Header;
    UCHAR DeviceSpecific[192];
} PCI_COMMON_CONFIG, *PPCI_COMMON_CONFIG;
#define PCI_COMMON_HDR_LENGTH (FIELD_OFFSET(PCI_COMMON_CONFIG, DeviceSpecific))

#define PCI_EXTENDED_CONFIG_LENGTH               0x1000

#define PCI_MAX_DEVICES        32
#define PCI_MAX_FUNCTION       8
#define PCI_MAX_BRIDGE_NUMBER  0xFF
#define PCI_INVALID_VENDORID   0xFFFF

/* PCI_COMMON_CONFIG.HeaderType */
#define PCI_MULTIFUNCTION                 0x80
#define PCI_DEVICE_TYPE                   0x00
#define PCI_BRIDGE_TYPE                   0x01
#define PCI_CARDBUS_BRIDGE_TYPE           0x02

#define PCI_CONFIGURATION_TYPE(PciData)					\
    (((PPCI_COMMON_CONFIG)(PciData))->Header.HeaderType & ~PCI_MULTIFUNCTION)

#define PCI_MULTIFUNCTION_DEVICE(PciData)				\
    ((((PPCI_COMMON_CONFIG)(PciData))->Header.HeaderType & PCI_MULTIFUNCTION) != 0)

/* PCI_COMMON_CONFIG.Command */
#define PCI_ENABLE_IO_SPACE               0x0001
#define PCI_ENABLE_MEMORY_SPACE           0x0002
#define PCI_ENABLE_BUS_MASTER             0x0004
#define PCI_ENABLE_SPECIAL_CYCLES         0x0008
#define PCI_ENABLE_WRITE_AND_INVALIDATE   0x0010
#define PCI_ENABLE_VGA_COMPATIBLE_PALETTE 0x0020
#define PCI_ENABLE_PARITY                 0x0040
#define PCI_ENABLE_WAIT_CYCLE             0x0080
#define PCI_ENABLE_SERR                   0x0100
#define PCI_ENABLE_FAST_BACK_TO_BACK      0x0200
#define PCI_DISABLE_LEVEL_INTERRUPT       0x0400

/* PCI_COMMON_CONFIG.Status */
#define PCI_STATUS_INTERRUPT_PENDING      0x0008
#define PCI_STATUS_CAPABILITIES_LIST      0x0010
#define PCI_STATUS_66MHZ_CAPABLE          0x0020
#define PCI_STATUS_UDF_SUPPORTED          0x0040
#define PCI_STATUS_FAST_BACK_TO_BACK      0x0080
#define PCI_STATUS_DATA_PARITY_DETECTED   0x0100
#define PCI_STATUS_DEVSEL                 0x0600
#define PCI_STATUS_SIGNALED_TARGET_ABORT  0x0800
#define PCI_STATUS_RECEIVED_TARGET_ABORT  0x1000
#define PCI_STATUS_RECEIVED_MASTER_ABORT  0x2000
#define PCI_STATUS_SIGNALED_SYSTEM_ERROR  0x4000
#define PCI_STATUS_DETECTED_PARITY_ERROR  0x8000

/* IO_STACK_LOCATION.Parameters.ReadWriteControl.WhichSpace */

#define PCI_WHICHSPACE_CONFIG             0x0
#define PCI_WHICHSPACE_ROM                0x52696350 /* 'PciR' */

#define PCI_CAPABILITY_ID_POWER_MANAGEMENT  0x01
#define PCI_CAPABILITY_ID_AGP               0x02
#define PCI_CAPABILITY_ID_VPD               0x03
#define PCI_CAPABILITY_ID_SLOT_ID           0x04
#define PCI_CAPABILITY_ID_MSI               0x05
#define PCI_CAPABILITY_ID_CPCI_HOTSWAP      0x06
#define PCI_CAPABILITY_ID_PCIX              0x07
#define PCI_CAPABILITY_ID_HYPERTRANSPORT    0x08
#define PCI_CAPABILITY_ID_VENDOR_SPECIFIC   0x09
#define PCI_CAPABILITY_ID_DEBUG_PORT        0x0A
#define PCI_CAPABILITY_ID_CPCI_RES_CTRL     0x0B
#define PCI_CAPABILITY_ID_SHPC              0x0C
#define PCI_CAPABILITY_ID_P2P_SSID          0x0D
#define PCI_CAPABILITY_ID_AGP_TARGET        0x0E
#define PCI_CAPABILITY_ID_SECURE            0x0F
#define PCI_CAPABILITY_ID_PCI_EXPRESS       0x10
#define PCI_CAPABILITY_ID_MSIX              0x11

typedef struct _PCI_CAPABILITIES_HEADER {
    UCHAR CapabilityID;
    UCHAR Next;
} PCI_CAPABILITIES_HEADER, *PPCI_CAPABILITIES_HEADER;

typedef struct _PCI_AGP_CAPABILITY {
    PCI_CAPABILITIES_HEADER Header;
    USHORT Minor:4;
    USHORT Major:4;
    USHORT Rsvd1:8;
    struct _PCI_AGP_STATUS {
	ULONG Rate:3;
	ULONG Agp3Mode:1;
	ULONG FastWrite:1;
	ULONG FourGB:1;
	ULONG HostTransDisable:1;
	ULONG Gart64:1;
	ULONG ITA_Coherent:1;
	ULONG SideBandAddressing:1;
	ULONG CalibrationCycle:3;
	ULONG AsyncRequestSize:3;
	ULONG Rsvd1:1;
	ULONG Isoch:1;
	ULONG Rsvd2:6;
	ULONG RequestQueueDepthMaximum:8;
    } AGPStatus;
    struct _PCI_AGP_COMMAND {
	ULONG Rate:3;
	ULONG Rsvd1:1;
	ULONG FastWriteEnable:1;
	ULONG FourGBEnable:1;
	ULONG Rsvd2:1;
	ULONG Gart64:1;
	ULONG AGPEnable:1;
	ULONG CalibrationCycle:3;
	ULONG AsyncReqSize:3;
	ULONG Rsvd3:8;
	ULONG RequestQueueDepth:8;
    } AGPCommand;
} PCI_AGP_CAPABILITY, *PPCI_AGP_CAPABILITY;

typedef enum _EXTENDED_AGP_REGISTER {
    IsochStatus,
    AgpControl,
    ApertureSize,
    AperturePageSize,
    GartLow,
    GartHigh,
    IsochCommand
} EXTENDED_AGP_REGISTER, *PEXTENDED_AGP_REGISTER;

typedef struct _PCI_AGP_ISOCH_STATUS {
    ULONG ErrorCode:2;
    ULONG Rsvd1:1;
    ULONG Isoch_L:3;
    ULONG Isoch_Y:2;
    ULONG Isoch_N:8;
    ULONG Rsvd2:16;
} PCI_AGP_ISOCH_STATUS, *PPCI_AGP_ISOCH_STATUS;

typedef struct _PCI_AGP_CONTROL {
    ULONG Rsvd1:7;
    ULONG GTLB_Enable:1;
    ULONG AP_Enable:1;
    ULONG CAL_Disable:1;
    ULONG Rsvd2:22;
} PCI_AGP_CONTROL, *PPCI_AGP_CONTROL;

typedef struct _PCI_AGP_APERTURE_PAGE_SIZE {
    USHORT PageSizeMask:11;
    USHORT Rsvd1:1;
    USHORT PageSizeSelect:4;
} PCI_AGP_APERTURE_PAGE_SIZE, *PPCI_AGP_APERTURE_PAGE_SIZE;

typedef struct _PCI_AGP_ISOCH_COMMAND {
    USHORT Rsvd1:6;
    USHORT Isoch_Y:2;
    USHORT Isoch_N:8;
} PCI_AGP_ISOCH_COMMAND, *PPCI_AGP_ISOCH_COMMAND;

typedef struct PCI_AGP_EXTENDED_CAPABILITY {
    PCI_AGP_ISOCH_STATUS IsochStatus;
    PCI_AGP_CONTROL AgpControl;
    USHORT ApertureSize;
    PCI_AGP_APERTURE_PAGE_SIZE AperturePageSize;
    ULONG GartLow;
    ULONG GartHigh;
    PCI_AGP_ISOCH_COMMAND IsochCommand;
} PCI_AGP_EXTENDED_CAPABILITY, *PPCI_AGP_EXTENDED_CAPABILITY;

#define PCI_AGP_RATE_1X     0x1
#define PCI_AGP_RATE_2X     0x2
#define PCI_AGP_RATE_4X     0x4

#define PCIX_MODE_CONVENTIONAL_PCI  0x0
#define PCIX_MODE1_66MHZ            0x1
#define PCIX_MODE1_100MHZ           0x2
#define PCIX_MODE1_133MHZ           0x3
#define PCIX_MODE2_266_66MHZ        0x9
#define PCIX_MODE2_266_100MHZ       0xA
#define PCIX_MODE2_266_133MHZ       0xB
#define PCIX_MODE2_533_66MHZ        0xD
#define PCIX_MODE2_533_100MHZ       0xE
#define PCIX_MODE2_533_133MHZ       0xF

#define PCIX_VERSION_MODE1_ONLY     0x0
#define PCIX_VERSION_MODE2_ECC      0x1
#define PCIX_VERSION_DUAL_MODE_ECC  0x2

typedef struct _PCI_PMC {
    UCHAR Version:3;
    UCHAR PMEClock:1;
    UCHAR Rsvd1:1;
    UCHAR DeviceSpecificInitialization:1;
    UCHAR Rsvd2:2;
    struct _PM_SUPPORT {
	UCHAR Rsvd2:1;
	UCHAR D1:1;
	UCHAR D2:1;
	UCHAR PMED0:1;
	UCHAR PMED1:1;
	UCHAR PMED2:1;
	UCHAR PMED3Hot:1;
	UCHAR PMED3Cold:1;
    } Support;
} PCI_PMC, *PPCI_PMC;

typedef struct _PCI_PMCSR {
    USHORT PowerState:2;
    USHORT Rsvd1:6;
    USHORT PMEEnable:1;
    USHORT DataSelect:4;
    USHORT DataScale:2;
    USHORT PMEStatus:1;
} PCI_PMCSR, *PPCI_PMCSR;

typedef struct _PCI_PMCSR_BSE {
    UCHAR Rsvd1:6;
    UCHAR D3HotSupportsStopClock:1;
    UCHAR BusPowerClockControlEnabled:1;
} PCI_PMCSR_BSE, *PPCI_PMCSR_BSE;

typedef struct _PCI_PM_CAPABILITY {
    PCI_CAPABILITIES_HEADER Header;
    union {
	PCI_PMC Capabilities;
	USHORT AsUSHORT;
    } PMC;
    union {
	PCI_PMCSR ControlStatus;
	USHORT AsUSHORT;
    } PMCSR;
    union {
	PCI_PMCSR_BSE BridgeSupport;
	UCHAR AsUCHAR;
    } PMCSR_BSE;
    UCHAR Data;
} PCI_PM_CAPABILITY, *PPCI_PM_CAPABILITY;

typedef struct _PCI_X_CAPABILITY {
    PCI_CAPABILITIES_HEADER Header;
    union {
	struct {
	    USHORT DataParityErrorRecoveryEnable:1;
	    USHORT EnableRelaxedOrdering:1;
	    USHORT MaxMemoryReadByteCount:2;
	    USHORT MaxOutstandingSplitTransactions:3;
	    USHORT Reserved:9;
	} Bits;
	USHORT AsUSHORT;
    } Command;
    union {
	struct {
	    ULONG FunctionNumber:3;
	    ULONG DeviceNumber:5;
	    ULONG BusNumber:8;
	    ULONG Device64Bit:1;
	    ULONG Capable133MHz:1;
	    ULONG SplitCompletionDiscarded:1;
	    ULONG UnexpectedSplitCompletion:1;
	    ULONG DeviceComplexity:1;
	    ULONG DesignedMaxMemoryReadByteCount:2;
	    ULONG DesignedMaxOutstandingSplitTransactions:3;
	    ULONG DesignedMaxCumulativeReadSize:3;
	    ULONG ReceivedSplitCompletionErrorMessage:1;
	    ULONG CapablePCIX266:1;
	    ULONG CapablePCIX533:1;
	} Bits;
	ULONG AsULONG;
    } Status;
} PCI_X_CAPABILITY, *PPCI_X_CAPABILITY;

typedef struct _PCIX_BRIDGE_CAPABILITY {
    PCI_CAPABILITIES_HEADER Header;
    union {
	struct {
	    USHORT Bus64Bit:1;
	    USHORT Bus133MHzCapable:1;
	    USHORT SplitCompletionDiscarded:1;
	    USHORT UnexpectedSplitCompletion:1;
	    USHORT SplitCompletionOverrun:1;
	    USHORT SplitRequestDelayed:1;
	    USHORT BusModeFrequency:4;
	    USHORT Rsvd:2;
	    USHORT Version:2;
	    USHORT Bus266MHzCapable:1;
	    USHORT Bus533MHzCapable:1;
	};
	USHORT AsUSHORT;
    } SecondaryStatus;
    union {
	struct {
	    ULONG FunctionNumber:3;
	    ULONG DeviceNumber:5;
	    ULONG BusNumber:8;
	    ULONG Device64Bit:1;
	    ULONG Device133MHzCapable:1;
	    ULONG SplitCompletionDiscarded:1;
	    ULONG UnexpectedSplitCompletion:1;
	    ULONG SplitCompletionOverrun:1;
	    ULONG SplitRequestDelayed:1;
	    ULONG Rsvd:7;
	    ULONG DIMCapable:1;
	    ULONG Device266MHzCapable:1;
	    ULONG Device533MHzCapable:1;
	};
	ULONG AsULONG;
    } BridgeStatus;
    USHORT UpstreamSplitTransactionCapacity;
    USHORT UpstreamSplitTransactionLimit;
    USHORT DownstreamSplitTransactionCapacity;
    USHORT DownstreamSplitTransactionLimit;
    union {
	struct {
	    ULONG SelectSecondaryRegisters:1;
	    ULONG ErrorPresentInOtherBank:1;
	    ULONG AdditionalCorrectableError:1;
	    ULONG AdditionalUncorrectableError:1;
	    ULONG ErrorPhase:3;
	    ULONG ErrorCorrected:1;
	    ULONG Syndrome:8;
	    ULONG ErrorFirstCommand:4;
	    ULONG ErrorSecondCommand:4;
	    ULONG ErrorUpperAttributes:4;
	    ULONG ControlUpdateEnable:1;
	    ULONG Rsvd:1;
	    ULONG DisableSingleBitCorrection:1;
	    ULONG EccMode:1;
	};
	ULONG AsULONG;
    } EccControlStatus;
    ULONG EccFirstAddress;
    ULONG EccSecondAddress;
    ULONG EccAttribute;
} PCIX_BRIDGE_CAPABILITY, *PPCIX_BRIDGE_CAPABILITY;

typedef struct _PCI_SUBSYSTEM_IDS_CAPABILITY {
    PCI_CAPABILITIES_HEADER Header;
    USHORT Reserved;
    USHORT SubVendorID;
    USHORT SubSystemID;
} PCI_SUBSYSTEM_IDS_CAPABILITY, *PPCI_SUBSYSTEM_IDS_CAPABILITY;

#define OSC_FIRMWARE_FAILURE                            0x02
#define OSC_UNRECOGNIZED_UUID                           0x04
#define OSC_UNRECOGNIZED_REVISION                       0x08
#define OSC_CAPABILITIES_MASKED                         0x10

#define PCI_ROOT_BUS_OSC_METHOD_CAPABILITY_REVISION     0x01

typedef union _PCI_ROOT_BUS_OSC_SUPPORT_FIELD {
    struct {
	ULONG ExtendedConfigOpRegions:1;
	ULONG ActiveStatePowerManagement:1;
	ULONG ClockPowerManagement:1;
	ULONG SegmentGroups:1;
	ULONG MessageSignaledInterrupts:1;
	ULONG WindowsHardwareErrorArchitecture:1;
	ULONG Reserved:26;
    };
    ULONG AsULONG;
} PCI_ROOT_BUS_OSC_SUPPORT_FIELD, *PPCI_ROOT_BUS_OSC_SUPPORT_FIELD;

typedef union _PCI_ROOT_BUS_OSC_CONTROL_FIELD {
    struct {
	ULONG ExpressNativeHotPlug:1;
	ULONG ShpcNativeHotPlug:1;
	ULONG ExpressNativePME:1;
	ULONG ExpressAdvancedErrorReporting:1;
	ULONG ExpressCapabilityStructure:1;
	ULONG Reserved:27;
    };
    ULONG AsULONG;
} PCI_ROOT_BUS_OSC_CONTROL_FIELD, *PPCI_ROOT_BUS_OSC_CONTROL_FIELD;

typedef enum _PCI_HARDWARE_INTERFACE {
    PciConventional,
    PciXMode1,
    PciXMode2,
    PciExpress
} PCI_HARDWARE_INTERFACE, *PPCI_HARDWARE_INTERFACE;

typedef enum {
    BusWidth32Bits,
    BusWidth64Bits
} PCI_BUS_WIDTH;

#define PCI_EXPRESS_ADVANCED_ERROR_REPORTING_CAP_ID                     0x0001
#define PCI_EXPRESS_VIRTUAL_CHANNEL_CAP_ID                              0x0002
#define PCI_EXPRESS_DEVICE_SERIAL_NUMBER_CAP_ID                         0x0003
#define PCI_EXPRESS_POWER_BUDGETING_CAP_ID                              0x0004
#define PCI_EXPRESS_RC_LINK_DECLARATION_CAP_ID                          0x0005
#define PCI_EXPRESS_RC_INTERNAL_LINK_CONTROL_CAP_ID                     0x0006
#define PCI_EXPRESS_RC_EVENT_COLLECTOR_ENDPOINT_ASSOCIATION_CAP_ID      0x0007
#define PCI_EXPRESS_MFVC_CAP_ID                                         0x0008
#define PCI_EXPRESS_VC_AND_MFVC_CAP_ID                                  0x0009
#define PCI_EXPRESS_RCRB_HEADER_CAP_ID                                  0x000A
#define PCI_EXPRESS_SINGLE_ROOT_IO_VIRTUALIZATION_CAP_ID                0x0010

typedef struct _PCI_EXPRESS_ENHANCED_CAPABILITY_HEADER {
    USHORT CapabilityID;
    USHORT Version:4;
    USHORT Next:12;
} PCI_EXPRESS_ENHANCED_CAPABILITY_HEADER, *PPCI_EXPRESS_ENHANCED_CAPABILITY_HEADER;

typedef struct _PCI_EXPRESS_SERIAL_NUMBER_CAPABILITY {
    PCI_EXPRESS_ENHANCED_CAPABILITY_HEADER Header;
    ULONG LowSerialNumber;
    ULONG HighSerialNumber;
} PCI_EXPRESS_SERIAL_NUMBER_CAPABILITY, *PPCI_EXPRESS_SERIAL_NUMBER_CAPABILITY;

typedef union _PCI_EXPRESS_UNCORRECTABLE_ERROR_STATUS {
    struct {
	ULONG Undefined:1;
	ULONG Reserved1:3;
	ULONG DataLinkProtocolError:1;
	ULONG SurpriseDownError:1;
	ULONG Reserved2:6;
	ULONG PoisonedTLP:1;
	ULONG FlowControlProtocolError:1;
	ULONG CompletionTimeout:1;
	ULONG CompleterAbort:1;
	ULONG UnexpectedCompletion:1;
	ULONG ReceiverOverflow:1;
	ULONG MalformedTLP:1;
	ULONG ECRCError:1;
	ULONG UnsupportedRequestError:1;
	ULONG Reserved3:11;
    };
    ULONG AsULONG;
} PCI_EXPRESS_UNCORRECTABLE_ERROR_STATUS, *PPCI_EXPRESS_UNCORRECTABLE_ERROR_STATUS;

typedef union _PCI_EXPRESS_UNCORRECTABLE_ERROR_MASK {
    struct {
	ULONG Undefined:1;
	ULONG Reserved1:3;
	ULONG DataLinkProtocolError:1;
	ULONG SurpriseDownError:1;
	ULONG Reserved2:6;
	ULONG PoisonedTLP:1;
	ULONG FlowControlProtocolError:1;
	ULONG CompletionTimeout:1;
	ULONG CompleterAbort:1;
	ULONG UnexpectedCompletion:1;
	ULONG ReceiverOverflow:1;
	ULONG MalformedTLP:1;
	ULONG ECRCError:1;
	ULONG UnsupportedRequestError:1;
	ULONG Reserved3:11;
    };
    ULONG AsULONG;
} PCI_EXPRESS_UNCORRECTABLE_ERROR_MASK, *PPCI_EXPRESS_UNCORRECTABLE_ERROR_MASK;

typedef union _PCI_EXPRESS_UNCORRECTABLE_ERROR_SEVERITY {
    struct {
	ULONG Undefined:1;
	ULONG Reserved1:3;
	ULONG DataLinkProtocolError:1;
	ULONG SurpriseDownError:1;
	ULONG Reserved2:6;
	ULONG PoisonedTLP:1;
	ULONG FlowControlProtocolError:1;
	ULONG CompletionTimeout:1;
	ULONG CompleterAbort:1;
	ULONG UnexpectedCompletion:1;
	ULONG ReceiverOverflow:1;
	ULONG MalformedTLP:1;
	ULONG ECRCError:1;
	ULONG UnsupportedRequestError:1;
	ULONG Reserved3:11;
    };
    ULONG AsULONG;
} PCI_EXPRESS_UNCORRECTABLE_ERROR_SEVERITY, *PPCI_EXPRESS_UNCORRECTABLE_ERROR_SEVERITY;

typedef union _PCI_EXPRESS_CORRECTABLE_ERROR_STATUS {
    struct {
	ULONG ReceiverError:1;
	ULONG Reserved1:5;
	ULONG BadTLP:1;
	ULONG BadDLLP:1;
	ULONG ReplayNumRollover:1;
	ULONG Reserved2:3;
	ULONG ReplayTimerTimeout:1;
	ULONG AdvisoryNonFatalError:1;
	ULONG Reserved3:18;
    };
    ULONG AsULONG;
} PCI_EXPRESS_CORRECTABLE_ERROR_STATUS, *PPCI_CORRECTABLE_ERROR_STATUS;

typedef union _PCI_EXPRESS_CORRECTABLE_ERROR_MASK {
    struct {
	ULONG ReceiverError:1;
	ULONG Reserved1:5;
	ULONG BadTLP:1;
	ULONG BadDLLP:1;
	ULONG ReplayNumRollover:1;
	ULONG Reserved2:3;
	ULONG ReplayTimerTimeout:1;
	ULONG AdvisoryNonFatalError:1;
	ULONG Reserved3:18;
    };
    ULONG AsULONG;
} PCI_EXPRESS_CORRECTABLE_ERROR_MASK, *PPCI_CORRECTABLE_ERROR_MASK;

typedef union _PCI_EXPRESS_AER_CAPABILITIES {
    struct {
	ULONG FirstErrorPointer:5;
	ULONG ECRCGenerationCapable:1;
	ULONG ECRCGenerationEnable:1;
	ULONG ECRCCheckCapable:1;
	ULONG ECRCCheckEnable:1;
	ULONG Reserved:23;
    };
    ULONG AsULONG;
} PCI_EXPRESS_AER_CAPABILITIES, *PPCI_EXPRESS_AER_CAPABILITIES;

typedef union _PCI_EXPRESS_ROOT_ERROR_COMMAND {
    struct {
	ULONG CorrectableErrorReportingEnable:1;
	ULONG NonFatalErrorReportingEnable:1;
	ULONG FatalErrorReportingEnable:1;
	ULONG Reserved:29;
    };
    ULONG AsULONG;
} PCI_EXPRESS_ROOT_ERROR_COMMAND, *PPCI_EXPRESS_ROOT_ERROR_COMMAND;

typedef union _PCI_EXPRESS_ROOT_ERROR_STATUS {
    struct {
	ULONG CorrectableErrorReceived:1;
	ULONG MultipleCorrectableErrorsReceived:1;
	ULONG UncorrectableErrorReceived:1;
	ULONG MultipleUncorrectableErrorsReceived:1;
	ULONG FirstUncorrectableFatal:1;
	ULONG NonFatalErrorMessagesReceived:1;
	ULONG FatalErrorMessagesReceived:1;
	ULONG Reserved:20;
	ULONG AdvancedErrorInterruptMessageNumber:5;
    };
    ULONG AsULONG;
} PCI_EXPRESS_ROOT_ERROR_STATUS, *PPCI_EXPRESS_ROOT_ERROR_STATUS;

typedef union _PCI_EXPRESS_ERROR_SOURCE_ID {
    struct {
	USHORT CorrectableSourceIdFun:3;
	USHORT CorrectableSourceIdDev:5;
	USHORT CorrectableSourceIdBus:8;
	USHORT UncorrectableSourceIdFun:3;
	USHORT UncorrectableSourceIdDev:5;
	USHORT UncorrectableSourceIdBus:8;
    };
    ULONG AsULONG;
} PCI_EXPRESS_ERROR_SOURCE_ID, *PPCI_EXPRESS_ERROR_SOURCE_ID;

typedef union _PCI_EXPRESS_SEC_UNCORRECTABLE_ERROR_STATUS {
    struct {
	ULONG TargetAbortOnSplitCompletion:1;
	ULONG MasterAbortOnSplitCompletion:1;
	ULONG ReceivedTargetAbort:1;
	ULONG ReceivedMasterAbort:1;
	ULONG RsvdZ:1;
	ULONG UnexpectedSplitCompletionError:1;
	ULONG UncorrectableSplitCompletion:1;
	ULONG UncorrectableDataError:1;
	ULONG UncorrectableAttributeError:1;
	ULONG UncorrectableAddressError:1;
	ULONG DelayedTransactionDiscardTimerExpired:1;
	ULONG PERRAsserted:1;
	ULONG SERRAsserted:1;
	ULONG InternalBridgeError:1;
	ULONG Reserved:18;
    };
    ULONG AsULONG;
} PCI_EXPRESS_SEC_UNCORRECTABLE_ERROR_STATUS, *PPCI_EXPRESS_SEC_UNCORRECTABLE_ERROR_STATUS;

typedef union _PCI_EXPRESS_SEC_UNCORRECTABLE_ERROR_MASK {
    struct {
	ULONG TargetAbortOnSplitCompletion:1;
	ULONG MasterAbortOnSplitCompletion:1;
	ULONG ReceivedTargetAbort:1;
	ULONG ReceivedMasterAbort:1;
	ULONG RsvdZ:1;
	ULONG UnexpectedSplitCompletionError:1;
	ULONG UncorrectableSplitCompletion:1;
	ULONG UncorrectableDataError:1;
	ULONG UncorrectableAttributeError:1;
	ULONG UncorrectableAddressError:1;
	ULONG DelayedTransactionDiscardTimerExpired:1;
	ULONG PERRAsserted:1;
	ULONG SERRAsserted:1;
	ULONG InternalBridgeError:1;
	ULONG Reserved:18;
    };
    ULONG AsULONG;
} PCI_EXPRESS_SEC_UNCORRECTABLE_ERROR_MASK, *PPCI_EXPRESS_SEC_UNCORRECTABLE_ERROR_MASK;

typedef union _PCI_EXPRESS_SEC_UNCORRECTABLE_ERROR_SEVERITY {
    struct {
	ULONG TargetAbortOnSplitCompletion:1;
	ULONG MasterAbortOnSplitCompletion:1;
	ULONG ReceivedTargetAbort:1;
	ULONG ReceivedMasterAbort:1;
	ULONG RsvdZ:1;
	ULONG UnexpectedSplitCompletionError:1;
	ULONG UncorrectableSplitCompletion:1;
	ULONG UncorrectableDataError:1;
	ULONG UncorrectableAttributeError:1;
	ULONG UncorrectableAddressError:1;
	ULONG DelayedTransactionDiscardTimerExpired:1;
	ULONG PERRAsserted:1;
	ULONG SERRAsserted:1;
	ULONG InternalBridgeError:1;
	ULONG Reserved:18;
    };
    ULONG AsULONG;
} PCI_EXPRESS_SEC_UNCORRECTABLE_ERROR_SEVERITY, *PPCI_EXPRESS_SEC_UNCORRECTABLE_ERROR_SEVERITY;

typedef union _PCI_EXPRESS_SEC_AER_CAPABILITIES {
    struct {
	ULONG SecondaryUncorrectableFirstErrorPtr:5;
	ULONG Reserved:27;
    };
    ULONG AsULONG;
} PCI_EXPRESS_SEC_AER_CAPABILITIES, *PPCI_EXPRESS_SEC_AER_CAPABILITIES;

#define ROOT_CMD_ENABLE_CORRECTABLE_ERROR_REPORTING  0x00000001
#define ROOT_CMD_ENABLE_NONFATAL_ERROR_REPORTING     0x00000002
#define ROOT_CMD_ENABLE_FATAL_ERROR_REPORTING        0x00000004

#define ROOT_CMD_ERROR_REPORTING_ENABLE_MASK		\
    (ROOT_CMD_ENABLE_FATAL_ERROR_REPORTING |		\
     ROOT_CMD_ENABLE_NONFATAL_ERROR_REPORTING |		\
     ROOT_CMD_ENABLE_CORRECTABLE_ERROR_REPORTING)

typedef struct _PCI_EXPRESS_AER_CAPABILITY {
    PCI_EXPRESS_ENHANCED_CAPABILITY_HEADER Header;
    PCI_EXPRESS_UNCORRECTABLE_ERROR_STATUS UncorrectableErrorStatus;
    PCI_EXPRESS_UNCORRECTABLE_ERROR_MASK UncorrectableErrorMask;
    PCI_EXPRESS_UNCORRECTABLE_ERROR_SEVERITY UncorrectableErrorSeverity;
    PCI_EXPRESS_CORRECTABLE_ERROR_STATUS CorrectableErrorStatus;
    PCI_EXPRESS_CORRECTABLE_ERROR_MASK CorrectableErrorMask;
    PCI_EXPRESS_AER_CAPABILITIES CapabilitiesAndControl;
    ULONG HeaderLog[4];
    PCI_EXPRESS_SEC_UNCORRECTABLE_ERROR_STATUS SecUncorrectableErrorStatus;
    PCI_EXPRESS_SEC_UNCORRECTABLE_ERROR_MASK SecUncorrectableErrorMask;
    PCI_EXPRESS_SEC_UNCORRECTABLE_ERROR_SEVERITY SecUncorrectableErrorSeverity;
    PCI_EXPRESS_SEC_AER_CAPABILITIES SecCapabilitiesAndControl;
    ULONG SecHeaderLog[4];
} PCI_EXPRESS_AER_CAPABILITY, *PPCI_EXPRESS_AER_CAPABILITY;

typedef struct _PCI_EXPRESS_ROOTPORT_AER_CAPABILITY {
    PCI_EXPRESS_ENHANCED_CAPABILITY_HEADER Header;
    PCI_EXPRESS_UNCORRECTABLE_ERROR_STATUS UncorrectableErrorStatus;
    PCI_EXPRESS_UNCORRECTABLE_ERROR_MASK UncorrectableErrorMask;
    PCI_EXPRESS_UNCORRECTABLE_ERROR_SEVERITY UncorrectableErrorSeverity;
    PCI_EXPRESS_CORRECTABLE_ERROR_STATUS CorrectableErrorStatus;
    PCI_EXPRESS_CORRECTABLE_ERROR_MASK CorrectableErrorMask;
    PCI_EXPRESS_AER_CAPABILITIES CapabilitiesAndControl;
    ULONG HeaderLog[4];
    PCI_EXPRESS_ROOT_ERROR_COMMAND RootErrorCommand;
    PCI_EXPRESS_ROOT_ERROR_STATUS RootErrorStatus;
    PCI_EXPRESS_ERROR_SOURCE_ID ErrorSourceId;
} PCI_EXPRESS_ROOTPORT_AER_CAPABILITY, *PPCI_EXPRESS_ROOTPORT_AER_CAPABILITY;

typedef struct _PCI_EXPRESS_BRIDGE_AER_CAPABILITY {
    PCI_EXPRESS_ENHANCED_CAPABILITY_HEADER Header;
    PCI_EXPRESS_UNCORRECTABLE_ERROR_STATUS UncorrectableErrorStatus;
    PCI_EXPRESS_UNCORRECTABLE_ERROR_MASK UncorrectableErrorMask;
    PCI_EXPRESS_UNCORRECTABLE_ERROR_SEVERITY UncorrectableErrorSeverity;
    PCI_EXPRESS_CORRECTABLE_ERROR_STATUS CorrectableErrorStatus;
    PCI_EXPRESS_CORRECTABLE_ERROR_MASK CorrectableErrorMask;
    PCI_EXPRESS_AER_CAPABILITIES CapabilitiesAndControl;
    ULONG HeaderLog[4];
    PCI_EXPRESS_SEC_UNCORRECTABLE_ERROR_STATUS SecUncorrectableErrorStatus;
    PCI_EXPRESS_SEC_UNCORRECTABLE_ERROR_MASK SecUncorrectableErrorMask;
    PCI_EXPRESS_SEC_UNCORRECTABLE_ERROR_SEVERITY SecUncorrectableErrorSeverity;
    PCI_EXPRESS_SEC_AER_CAPABILITIES SecCapabilitiesAndControl;
    ULONG SecHeaderLog[4];
} PCI_EXPRESS_BRIDGE_AER_CAPABILITY, *PPCI_EXPRESS_BRIDGE_AER_CAPABILITY;

typedef union _PCI_EXPRESS_SRIOV_CAPS {
    struct {
	ULONG VFMigrationCapable:1;
	ULONG Reserved1:20;
	ULONG VFMigrationInterruptNumber:11;
    };
    ULONG AsULONG;
} PCI_EXPRESS_SRIOV_CAPS, *PPCI_EXPRESS_SRIOV_CAPS;

typedef union _PCI_EXPRESS_SRIOV_CONTROL {
    struct {
	USHORT VFEnable:1;
	USHORT VFMigrationEnable:1;
	USHORT VFMigrationInterruptEnable:1;
	USHORT VFMemorySpaceEnable:1;
	USHORT ARICapableHierarchy:1;
	USHORT Reserved1:11;
    };
    USHORT AsUSHORT;
} PCI_EXPRESS_SRIOV_CONTROL, *PPCI_EXPRESS_SRIOV_CONTROL;

typedef union _PCI_EXPRESS_SRIOV_STATUS {
    struct {
	USHORT VFMigrationStatus:1;
	USHORT Reserved1:15;
    };
    USHORT AsUSHORT;
} PCI_EXPRESS_SRIOV_STATUS, *PPCI_EXPRESS_SRIOV_STATUS;

typedef union _PCI_EXPRESS_SRIOV_MIGRATION_STATE_ARRAY {
    struct {
	ULONG VFMigrationStateBIR:3;
	ULONG VFMigrationStateOffset:29;
    };
    ULONG AsULONG;
} PCI_EXPRESS_SRIOV_MIGRATION_STATE_ARRAY, *PPCI_EXPRESS_SRIOV_MIGRATION_STATE_ARRAY;

typedef struct _PCI_EXPRESS_SRIOV_CAPABILITY {
    PCI_EXPRESS_ENHANCED_CAPABILITY_HEADER Header;
    PCI_EXPRESS_SRIOV_CAPS SRIOVCapabilities;
    PCI_EXPRESS_SRIOV_CONTROL SRIOVControl;
    PCI_EXPRESS_SRIOV_STATUS SRIOVStatus;
    USHORT InitialVFs;
    USHORT TotalVFs;
    USHORT NumVFs;
    UCHAR FunctionDependencyLink;
    UCHAR RsvdP1;
    USHORT FirstVFOffset;
    USHORT VFStride;
    USHORT RsvdP2;
    USHORT VFDeviceId;
    ULONG SupportedPageSizes;
    ULONG SystemPageSize;
    ULONG BaseAddresses[PCI_TYPE0_ADDRESSES];
    PCI_EXPRESS_SRIOV_MIGRATION_STATE_ARRAY VFMigrationStateArrayOffset;
} PCI_EXPRESS_SRIOV_CAPABILITY, *PPCI_EXPRESS_SRIOV_CAPABILITY;

/* PCI device classes */
#define PCI_CLASS_PRE_20                    0x00
#define PCI_CLASS_MASS_STORAGE_CTLR         0x01
#define PCI_CLASS_NETWORK_CTLR              0x02
#define PCI_CLASS_DISPLAY_CTLR              0x03
#define PCI_CLASS_MULTIMEDIA_DEV            0x04
#define PCI_CLASS_MEMORY_CTLR               0x05
#define PCI_CLASS_BRIDGE_DEV                0x06
#define PCI_CLASS_SIMPLE_COMMS_CTLR         0x07
#define PCI_CLASS_BASE_SYSTEM_DEV           0x08
#define PCI_CLASS_INPUT_DEV                 0x09
#define PCI_CLASS_DOCKING_STATION           0x0a
#define PCI_CLASS_PROCESSOR                 0x0b
#define PCI_CLASS_SERIAL_BUS_CTLR           0x0c
#define PCI_CLASS_WIRELESS_CTLR             0x0d
#define PCI_CLASS_INTELLIGENT_IO_CTLR       0x0e
#define PCI_CLASS_SATELLITE_COMMS_CTLR      0x0f
#define PCI_CLASS_ENCRYPTION_DECRYPTION     0x10
#define PCI_CLASS_DATA_ACQ_SIGNAL_PROC      0x11
#define PCI_CLASS_NOT_DEFINED               0xff

/* PCI device subclasses for class 0 */
#define PCI_SUBCLASS_PRE_20_NON_VGA         0x00
#define PCI_SUBCLASS_PRE_20_VGA             0x01

/* PCI device subclasses for class 1 (mass storage controllers)*/
#define PCI_SUBCLASS_MSC_SCSI_BUS_CTLR      0x00
#define PCI_SUBCLASS_MSC_IDE_CTLR           0x01
#define PCI_SUBCLASS_MSC_FLOPPY_CTLR        0x02
#define PCI_SUBCLASS_MSC_IPI_CTLR           0x03
#define PCI_SUBCLASS_MSC_RAID_CTLR          0x04
#define PCI_SUBCLASS_MSC_OTHER              0x80

/* PCI device subclasses for class 2 (network controllers)*/
#define PCI_SUBCLASS_NET_ETHERNET_CTLR      0x00
#define PCI_SUBCLASS_NET_TOKEN_RING_CTLR    0x01
#define PCI_SUBCLASS_NET_FDDI_CTLR          0x02
#define PCI_SUBCLASS_NET_ATM_CTLR           0x03
#define PCI_SUBCLASS_NET_ISDN_CTLR          0x04
#define PCI_SUBCLASS_NET_OTHER              0x80

/* PCI device subclasses for class 3 (display controllers)*/
#define PCI_SUBCLASS_VID_VGA_CTLR           0x00
#define PCI_SUBCLASS_VID_XGA_CTLR           0x01
#define PCI_SUBCLASS_VID_3D_CTLR            0x02
#define PCI_SUBCLASS_VID_OTHER              0x80

/* PCI device subclasses for class 4 (multimedia device)*/
#define PCI_SUBCLASS_MM_VIDEO_DEV           0x00
#define PCI_SUBCLASS_MM_AUDIO_DEV           0x01
#define PCI_SUBCLASS_MM_TELEPHONY_DEV       0x02
#define PCI_SUBCLASS_MM_OTHER               0x80

/* PCI device subclasses for class 5 (memory controller)*/
#define PCI_SUBCLASS_MEM_RAM                0x00
#define PCI_SUBCLASS_MEM_FLASH              0x01
#define PCI_SUBCLASS_MEM_OTHER              0x80

/* PCI device subclasses for class 6 (bridge device)*/
#define PCI_SUBCLASS_BR_HOST                0x00
#define PCI_SUBCLASS_BR_ISA                 0x01
#define PCI_SUBCLASS_BR_EISA                0x02
#define PCI_SUBCLASS_BR_MCA                 0x03
#define PCI_SUBCLASS_BR_PCI_TO_PCI          0x04
#define PCI_SUBCLASS_BR_PCMCIA              0x05
#define PCI_SUBCLASS_BR_NUBUS               0x06
#define PCI_SUBCLASS_BR_CARDBUS             0x07
#define PCI_SUBCLASS_BR_RACEWAY             0x08
#define PCI_SUBCLASS_BR_OTHER               0x80

#define PCI_SUBCLASS_COM_SERIAL             0x00
#define PCI_SUBCLASS_COM_PARALLEL           0x01
#define PCI_SUBCLASS_COM_MULTIPORT          0x02
#define PCI_SUBCLASS_COM_MODEM              0x03
#define PCI_SUBCLASS_COM_OTHER              0x80

#define PCI_SUBCLASS_SYS_INTERRUPT_CTLR     0x00
#define PCI_SUBCLASS_SYS_DMA_CTLR           0x01
#define PCI_SUBCLASS_SYS_SYSTEM_TIMER       0x02
#define PCI_SUBCLASS_SYS_REAL_TIME_CLOCK    0x03
#define PCI_SUBCLASS_SYS_GEN_HOTPLUG_CTLR   0x04
#define PCI_SUBCLASS_SYS_SDIO_CTRL          0x05
#define PCI_SUBCLASS_SYS_OTHER              0x80

#define PCI_SUBCLASS_INP_KEYBOARD           0x00
#define PCI_SUBCLASS_INP_DIGITIZER          0x01
#define PCI_SUBCLASS_INP_MOUSE              0x02
#define PCI_SUBCLASS_INP_SCANNER            0x03
#define PCI_SUBCLASS_INP_GAMEPORT           0x04
#define PCI_SUBCLASS_INP_OTHER              0x80

#define PCI_SUBCLASS_DOC_GENERIC            0x00
#define PCI_SUBCLASS_DOC_OTHER              0x80

#define PCI_SUBCLASS_PROC_386               0x00
#define PCI_SUBCLASS_PROC_486               0x01
#define PCI_SUBCLASS_PROC_PENTIUM           0x02
#define PCI_SUBCLASS_PROC_ALPHA             0x10
#define PCI_SUBCLASS_PROC_POWERPC           0x20
#define PCI_SUBCLASS_PROC_COPROCESSOR       0x40

/* PCI device subclasses for class C (serial bus controller)*/
#define PCI_SUBCLASS_SB_IEEE1394            0x00
#define PCI_SUBCLASS_SB_ACCESS              0x01
#define PCI_SUBCLASS_SB_SSA                 0x02
#define PCI_SUBCLASS_SB_USB                 0x03
#define PCI_SUBCLASS_SB_FIBRE_CHANNEL       0x04
#define PCI_SUBCLASS_SB_SMBUS               0x05

#define PCI_SUBCLASS_WIRELESS_IRDA          0x00
#define PCI_SUBCLASS_WIRELESS_CON_IR        0x01
#define PCI_SUBCLASS_WIRELESS_RF            0x10
#define PCI_SUBCLASS_WIRELESS_OTHER         0x80

#define PCI_SUBCLASS_INTIO_I2O              0x00

#define PCI_SUBCLASS_SAT_TV                 0x01
#define PCI_SUBCLASS_SAT_AUDIO              0x02
#define PCI_SUBCLASS_SAT_VOICE              0x03
#define PCI_SUBCLASS_SAT_DATA               0x04

#define PCI_SUBCLASS_CRYPTO_NET_COMP        0x00
#define PCI_SUBCLASS_CRYPTO_ENTERTAINMENT   0x10
#define PCI_SUBCLASS_CRYPTO_OTHER           0x80

#define PCI_SUBCLASS_DASP_DPIO              0x00
#define PCI_SUBCLASS_DASP_OTHER             0x80

#define PCI_ADDRESS_IO_SPACE                0x00000001
#define PCI_ADDRESS_MEMORY_TYPE_MASK        0x00000006
#define PCI_ADDRESS_MEMORY_PREFETCHABLE     0x00000008
#define PCI_ADDRESS_IO_ADDRESS_MASK         0xfffffffc
#define PCI_ADDRESS_MEMORY_ADDRESS_MASK     0xfffffff0
#define PCI_ADDRESS_ROM_ADDRESS_MASK        0xfffff800

#define PCI_TYPE_32BIT                      0
#define PCI_TYPE_20BIT                      2
#define PCI_TYPE_64BIT                      4

#define PCI_ROMADDRESS_ENABLED              0x00000001

//
// PCI Hack Flags
//
#define PCI_HACK_LOCK_RESOURCES 0x0000000000000004LL
#define PCI_HACK_NO_ENUM_AT_ALL 0x0000000000000008LL
#define PCI_HACK_ENUM_NO_RESOURCE 0x0000000000000010LL
#define PCI_HACK_AVOID_D1D2_FOR_SLD 0x0000000000000020LL
#define PCI_HACK_NEVER_DISCONNECT 0x0000000000000040LL
#define PCI_HACK_DONT_DISABLE 0x0000000000000080LL
#define PCI_HACK_MULTIFUNCTION 0x0000000000000100LL
#define PCI_HACK_UNUSED_200 0x0000000000000200LL
#define PCI_HACK_IGNORE_NON_STICKY_ISA 0x0000000000000400LL
#define PCI_HACK_UNUSED_800 0x0000000000000800LL
#define PCI_HACK_DOUBLE_DECKER 0x0000000000001000LL
#define PCI_HACK_ONE_CHILD 0x0000000000002000LL
#define PCI_HACK_PRESERVE_COMMAND 0x0000000000004000LL
#define PCI_HACK_DEFAULT_CARDBUS_WINDOWS 0x0000000000008000LL
#define PCI_HACK_CB_SHARE_CMD_BITS 0x0000000000010000LL
#define PCI_HACK_IGNORE_ROOT_TOPOLOGY 0x0000000000020000LL
#define PCI_HACK_SUBTRACTIVE_DECODE 0x0000000000040000LL
#define PCI_HACK_NO_EXPRESS_CAP 0x0000000000080000LL
#define PCI_HACK_NO_ASPM_FOR_EXPRESS_LINK 0x0000000000100000LL
#define PCI_HACK_CLEAR_INT_DISABLE_FOR_MSI 0x0000000000200000LL
#define PCI_HACK_NO_SUBSYSTEM 0x0000000000400000LL
#define PCI_HACK_COMMAND_REWRITE 0x0000000000800000LL
#define PCI_HACK_AVOID_HARDWARE_ISA_BIT 0x0000000001000000LL
#define PCI_HACK_FORCE_BRIDGE_WINDOW_ALIGNMENT 0x0000000002000000LL
#define PCI_HACK_NOT_MSI_HT_CONVERTER 0x0000000004000000LL
#define PCI_HACK_PCI_HACK_SBR_ON_LINK_STATE_CHANGE 0x0000000008000000LL
#define PCI_HACK_PCI_HACK_LINK_DISABLE_ON_SLOT_PWRDN 0x0000000010000000LL
#define PCI_HACK_NO_PM_CAPS 0x0000000020000000LL
#define PCI_HACK_DONT_DISABLE_DECODES 0x0000000040000000LL
#define PCI_HACK_NO_SUBSYSTEM_AFTER_D3 0x0000000080000000LL
#define PCI_HACK_VIDEO_LEGACY_DECODE 0x0000000100000000LL
#define PCI_HACK_FAKE_CLASS_CODE 0x0000000200000000LL
#define PCI_HACK_UNUSED_40000000 0x0000000400000000LL
#define PCI_HACK_DISABLE_IDE_NATIVE_MODE 0x0000000800000000LL
#define PCI_HACK_FAIL_QUERY_REMOVE 0x0000001000000000LL
#define PCI_HACK_CRITICAL_DEVICE 0x0000002000000000LL
#define PCI_HACK_UNUSED_4000000000 0x0000004000000000LL
#define PCI_HACK_BROKEN_SUBTRACTIVE_DECODE 0x0000008000000000LL
#define PCI_HACK_NO_REVISION_AFTER_D3 0x0000010000000000LL
#define PCI_HACK_ENABLE_MSI_MAPPING 0x0000020000000000LL
#define PCI_HACK_DISABLE_PM_DOWNSTREAM_PCI_BRIDGE 0x0000040000000000LL
#define PCI_HACK_DISABLE_HOT_PLUG 0x0000080000000000LL
#define PCI_HACK_IGNORE_AER_CAPABILITY 0x0000100000000000LL

//
// Bit encodes for PCI_COMMON_CONFIG.u.type1.BridgeControl
//
#define PCI_ENABLE_BRIDGE_PARITY_ERROR 0x0001
#define PCI_ENABLE_BRIDGE_SERR 0x0002
#define PCI_ENABLE_BRIDGE_ISA 0x0004
#define PCI_ENABLE_BRIDGE_VGA 0x0008
#define PCI_ENABLE_BRIDGE_MASTER_ABORT_SERR 0x0020
#define PCI_ASSERT_BRIDGE_RESET 0x0040
#define PCI_ENABLE_BRIDGE_VGA_16BIT 0x0010

//
// PCI IRQ Routing Table in BIOS/Registry (Signature: PIR$)
//
#include <pshpack1.h>
typedef struct _PIN_INFO {
    UCHAR Link;
    USHORT InterruptMap;
} PIN_INFO, *PPIN_INFO;

typedef struct _SLOT_INFO {
    UCHAR BusNumber;
    UCHAR DeviceNumber;
    PIN_INFO PinInfo[4];
    UCHAR SlotNumber;
    UCHAR Reserved;
} SLOT_INFO, *PSLOT_INFO;

typedef struct _PCI_IRQ_ROUTING_TABLE {
    ULONG Signature;
    USHORT Version;
    USHORT TableSize;
    UCHAR RouterBus;
    UCHAR RouterDevFunc;
    USHORT ExclusiveIRQs;
    ULONG CompatibleRouter;
    ULONG MiniportData;
    UCHAR Reserved[11];
    UCHAR Checksum;
    SLOT_INFO Slot[ANYSIZE_ARRAY];
} PCI_IRQ_ROUTING_TABLE, *PPCI_IRQ_ROUTING_TABLE;
#include <poppack.h>

//
// PCI Registry Information
//
typedef struct _PCI_REGISTRY_INFO {
    UCHAR MajorRevision;
    UCHAR MinorRevision;
    UCHAR NoBuses; // Number Of Buses
    UCHAR HardwareMechanism;
} PCI_REGISTRY_INFO, *PPCI_REGISTRY_INFO;

//
// PCI Card Descriptor in Registry
//
typedef struct _PCI_CARD_DESCRIPTOR {
    ULONG Flags;
    USHORT VendorID;
    USHORT DeviceID;
    USHORT RevisionID;
    USHORT SubsystemVendorID;
    USHORT SubsystemID;
    USHORT Reserved;
} PCI_CARD_DESCRIPTOR, *PPCI_CARD_DESCRIPTOR;
