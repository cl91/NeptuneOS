#ifndef _SRBHELPER_H_
#define _SRBHELPER_H_

#include <scsi.h>
#include <srb.h>

#if !defined(SRBHELPER_ASSERT)
#define SRBHELPER_ASSERT NT_ASSERT
#endif

#if !defined(SRB_ALIGN_SIZEOF)
#define SRB_ALIGN_SIZEOF(x)						\
    (((ULONG_PTR)(sizeof(x) + sizeof(PVOID) - 1)) & ~(sizeof(PVOID) - 1))
#endif

#if defined(_NTSTORPORT_) || defined(_NTSTORPORTP_)
#define SrbMoveMemory(Destination, Source, Length)	\
    StorPortMoveMemory(Destination, Source, Length)
#else
#define SrbMoveMemory(Destination, Source, Length)	\
    RtlMoveMemory(Destination, Source, Length)
#endif

#define SrbCopyMemory(Destination, Source, Length)	\
    RtlCopyMemory(Destination, Source, Length)
#define SrbZeroMemory(Destination, Length)		\
    RtlZeroMemory(Destination, Length)
#define SrbEqualMemory(Source1, Source2, Length)	\
    RtlEqualMemory(Source1, Source2, Length)

FORCEINLINE PSRBEX_DATA SrbGetSrbExDataByIndex(IN PSTORAGE_REQUEST_BLOCK Srb,
					       IN ULONG SrbExDataIndex)
{
    PSRBEX_DATA srbExData = NULL;

    if ((SrbExDataIndex < Srb->NumSrbExData) && (Srb->SrbExDataOffset[SrbExDataIndex]) &&
	(Srb->SrbExDataOffset[SrbExDataIndex] >= sizeof(STORAGE_REQUEST_BLOCK)) &&
	(Srb->SrbExDataOffset[SrbExDataIndex] < Srb->SrbLength)) {
	srbExData = (PSRBEX_DATA)((PUCHAR)Srb + Srb->SrbExDataOffset[SrbExDataIndex]);
    }

    return srbExData;
}

FORCEINLINE PSRBEX_DATA SrbGetSrbExDataByType(IN PSTORAGE_REQUEST_BLOCK Srb,
					      IN SRBEXDATATYPE Type)
{
    if (Srb->NumSrbExData > 0) {
	PSRBEX_DATA srbExData = NULL;
	UCHAR i = 0;

	for (i = 0; i < Srb->NumSrbExData; i++) {
	    if (Srb->SrbExDataOffset[i] >= sizeof(STORAGE_REQUEST_BLOCK) &&
		Srb->SrbExDataOffset[i] < Srb->SrbLength) {
		srbExData = (PSRBEX_DATA)((PUCHAR)Srb + Srb->SrbExDataOffset[i]);
		if (srbExData->Type == Type) {
		    return srbExData;
		}
	    }
	}
    }

    return NULL;
}

FORCEINLINE PSRBEX_DATA SrbGetPrimarySrbExData(IN PSTORAGE_REQUEST_BLOCK Srb)
{
    switch (Srb->SrbFunction) {
    case SRB_FUNCTION_POWER:
	return SrbGetSrbExDataByType(Srb, SrbExDataTypePower);

    case SRB_FUNCTION_PNP:
	return SrbGetSrbExDataByType(Srb, SrbExDataTypePnP);

    case SRB_FUNCTION_WMI:
	return SrbGetSrbExDataByType(Srb, SrbExDataTypeWmi);

    case SRB_FUNCTION_EXECUTE_SCSI: {
	PSRBEX_DATA srbExData = NULL;
	UCHAR i = 0;

	for (i = 0; i < Srb->NumSrbExData; i++) {
	    if (Srb->SrbExDataOffset[i] >= sizeof(STORAGE_REQUEST_BLOCK) &&
		Srb->SrbExDataOffset[i] < Srb->SrbLength) {
		srbExData = (PSRBEX_DATA)((PUCHAR)Srb + Srb->SrbExDataOffset[i]);
		if (srbExData->Type == SrbExDataTypeScsiCdb16 ||
		    srbExData->Type == SrbExDataTypeScsiCdb32 ||
		    srbExData->Type == SrbExDataTypeScsiCdbVar) {
		    return srbExData;
		}
	    }
	}
	return NULL;
    }

    default:
	return NULL;
    }
}

FORCEINLINE PSTOR_ADDRESS SrbGetAddress(IN PSTORAGE_REQUEST_BLOCK Srb)
{
    PSTOR_ADDRESS storAddr = NULL;
    SRBHELPER_ASSERT(Srb->AddressOffset);

    if (Srb->AddressOffset) {
	storAddr = (PSTOR_ADDRESS)((PUCHAR)Srb + Srb->AddressOffset);
	SRBHELPER_ASSERT(storAddr->Type == STOR_ADDRESS_TYPE_BTL8);
    }

    return storAddr;
}

FORCEINLINE BOOLEAN SrbCopySrb(IN PSTORAGE_REQUEST_BLOCK DestinationSrb,
			       IN ULONG DestinationSrbLength,
			       IN PSTORAGE_REQUEST_BLOCK SourceSrb)
{
    BOOLEAN Status = FALSE;

    if (DestinationSrbLength >= SourceSrb->SrbLength) {
	SrbCopyMemory(DestinationSrb, SourceSrb, SourceSrb->SrbLength);
	Status = TRUE;
    }

    return Status;
}

FORCEINLINE VOID SrbZeroSrb(IN PSTORAGE_REQUEST_BLOCK Srb)
{
    ULONG srbLength = Srb->SrbLength;
    SrbZeroMemory(Srb, Srb->SrbLength);
    Srb->SrbLength = srbLength;
}

FORCEINLINE ULONG SrbGetSrbLength(IN PSTORAGE_REQUEST_BLOCK Srb)
{
    return Srb->SrbLength;
}

FORCEINLINE VOID SrbSetSrbLength(IN PSTORAGE_REQUEST_BLOCK Srb, IN ULONG Length)
{
    Srb->SrbLength = Length;
}

FORCEINLINE ULONG SrbGetDefaultSrbLengthFromFunction(IN ULONG SrbFunction)
{
    switch (SrbFunction) {
    case SRB_FUNCTION_PNP:
	return SRB_ALIGN_SIZEOF(STORAGE_REQUEST_BLOCK) +
	       SRB_ALIGN_SIZEOF(STOR_ADDR_BTL8) + SRB_ALIGN_SIZEOF(SRBEX_DATA_PNP);
    case SRB_FUNCTION_POWER:
	return SRB_ALIGN_SIZEOF(STORAGE_REQUEST_BLOCK) +
	       SRB_ALIGN_SIZEOF(STOR_ADDR_BTL8) + SRB_ALIGN_SIZEOF(SRBEX_DATA_POWER);
    case SRB_FUNCTION_WMI:
	return SRB_ALIGN_SIZEOF(STORAGE_REQUEST_BLOCK) +
	       SRB_ALIGN_SIZEOF(STOR_ADDR_BTL8) + SRB_ALIGN_SIZEOF(SRBEX_DATA_WMI);
    case SRB_FUNCTION_EXECUTE_SCSI:
	return SRB_ALIGN_SIZEOF(STORAGE_REQUEST_BLOCK) +
	       SRB_ALIGN_SIZEOF(STOR_ADDR_BTL8) + SRB_ALIGN_SIZEOF(SRBEX_DATA_SCSI_CDB16);
    case SRB_FUNCTION_IO_CONTROL:
	return SRB_ALIGN_SIZEOF(STORAGE_REQUEST_BLOCK) + SRB_ALIGN_SIZEOF(STOR_ADDR_BTL8);
    default:
	return SRB_ALIGN_SIZEOF(STORAGE_REQUEST_BLOCK) + SRB_ALIGN_SIZEOF(STOR_ADDR_BTL8);
    }
}

FORCEINLINE PCDB SrbGetScsiData(IN PSTORAGE_REQUEST_BLOCK SrbEx,
				IN OPTIONAL PUCHAR CdbLength8,
				IN OPTIONAL PULONG CdbLength32,
				IN OPTIONAL PUCHAR ScsiStatus,
				IN OPTIONAL PVOID *SenseInfoBuffer,
				IN OPTIONAL PUCHAR SenseInfoBufferLength)
{
    PCDB Cdb = NULL;
    ULONG i;
    PSRBEX_DATA SrbExData = NULL;
    BOOLEAN FoundEntry = FALSE;

    if (SrbEx->SrbFunction == SRB_FUNCTION_EXECUTE_SCSI) {
	SRBHELPER_ASSERT(SrbEx->NumSrbExData > 0);

	for (i = 0; i < SrbEx->NumSrbExData; i++) {
	    if ((SrbEx->SrbExDataOffset[i] < sizeof(STORAGE_REQUEST_BLOCK)) ||
		(SrbEx->SrbExDataOffset[i] >= SrbEx->SrbLength)) {
		SRBHELPER_ASSERT(FALSE);
		continue;
	    }

	    SrbExData = (PSRBEX_DATA)((PUCHAR)SrbEx + SrbEx->SrbExDataOffset[i]);

	    switch (SrbExData->Type) {
	    case SrbExDataTypeScsiCdb16:
		if (SrbEx->SrbExDataOffset[i] + sizeof(SRBEX_DATA_SCSI_CDB16) <=
		    SrbEx->SrbLength) {
		    FoundEntry = TRUE;
		    if (CdbLength8) {
			*CdbLength8 = ((PSRBEX_DATA_SCSI_CDB16)SrbExData)->CdbLength;
		    }

		    if (((PSRBEX_DATA_SCSI_CDB16)SrbExData)->CdbLength > 0) {
			Cdb = (PCDB)((PSRBEX_DATA_SCSI_CDB16)SrbExData)->Cdb;
		    }

		    if (ScsiStatus) {
			*ScsiStatus = ((PSRBEX_DATA_SCSI_CDB16)SrbExData)->ScsiStatus;
		    }

		    if (SenseInfoBuffer) {
			*SenseInfoBuffer =
			    ((PSRBEX_DATA_SCSI_CDB16)SrbExData)->SenseInfoBuffer;
		    }

		    if (SenseInfoBufferLength) {
			*SenseInfoBufferLength =
			    ((PSRBEX_DATA_SCSI_CDB16)SrbExData)->SenseInfoBufferLength;
		    }
		} else {
		    // Catch invalid offset
		    SRBHELPER_ASSERT(FALSE);
		}
		break;

	    case SrbExDataTypeScsiCdb32:
		if (SrbEx->SrbExDataOffset[i] + sizeof(SRBEX_DATA_SCSI_CDB32) <=
		    SrbEx->SrbLength) {
		    FoundEntry = TRUE;
		    if (CdbLength8) {
			*CdbLength8 = ((PSRBEX_DATA_SCSI_CDB32)SrbExData)->CdbLength;
		    }

		    if (((PSRBEX_DATA_SCSI_CDB32)SrbExData)->CdbLength > 0) {
			Cdb = (PCDB)((PSRBEX_DATA_SCSI_CDB32)SrbExData)->Cdb;
		    }

		    if (ScsiStatus) {
			*ScsiStatus = ((PSRBEX_DATA_SCSI_CDB32)SrbExData)->ScsiStatus;
		    }

		    if (SenseInfoBuffer) {
			*SenseInfoBuffer =
			    ((PSRBEX_DATA_SCSI_CDB32)SrbExData)->SenseInfoBuffer;
		    }

		    if (SenseInfoBufferLength) {
			*SenseInfoBufferLength =
			    ((PSRBEX_DATA_SCSI_CDB32)SrbExData)->SenseInfoBufferLength;
		    }
		} else {
		    // Catch invalid offset
		    SRBHELPER_ASSERT(FALSE);
		}
		break;

	    case SrbExDataTypeScsiCdbVar:
		if (SrbEx->SrbExDataOffset[i] + sizeof(SRBEX_DATA_SCSI_CDB_VAR) <=
		    SrbEx->SrbLength) {
		    FoundEntry = TRUE;
		    if (CdbLength32) {
			*CdbLength32 = ((PSRBEX_DATA_SCSI_CDB_VAR)SrbExData)->CdbLength;
		    }

		    if (((PSRBEX_DATA_SCSI_CDB_VAR)SrbExData)->CdbLength > 0) {
			Cdb = (PCDB)((PSRBEX_DATA_SCSI_CDB_VAR)SrbExData)->Cdb;
		    }

		    if (ScsiStatus) {
			*ScsiStatus = ((PSRBEX_DATA_SCSI_CDB_VAR)SrbExData)->ScsiStatus;
		    }

		    if (SenseInfoBuffer) {
			*SenseInfoBuffer =
			    ((PSRBEX_DATA_SCSI_CDB_VAR)SrbExData)->SenseInfoBuffer;
		    }

		    if (SenseInfoBufferLength) {
			*SenseInfoBufferLength =
			    ((PSRBEX_DATA_SCSI_CDB_VAR)SrbExData)->SenseInfoBufferLength;
		    }
		} else {
		    SRBHELPER_ASSERT(FALSE);
		}
		break;
	    default:
		SRBHELPER_ASSERT(FALSE);
	    }

	    if (FoundEntry) {
		break;
	    }
	}
    } else {
	if (CdbLength8) {
	    *CdbLength8 = 0;
	}

	if (CdbLength32) {
	    *CdbLength32 = 0;
	}

	if (ScsiStatus) {
	    *ScsiStatus = SCSISTAT_GOOD;
	}

	if (SenseInfoBuffer) {
	    *SenseInfoBuffer = NULL;
	}

	if (SenseInfoBufferLength) {
	    *SenseInfoBufferLength = 0;
	}
    }

    return Cdb;
}

FORCEINLINE VOID SrbSetScsiData(IN PSTORAGE_REQUEST_BLOCK SrbEx,
				IN OPTIONAL PUCHAR CdbLength8,
				IN OPTIONAL PULONG CdbLength32,
				IN OPTIONAL PUCHAR ScsiStatus,
				IN OPTIONAL PVOID *SenseInfoBuffer,
				IN OPTIONAL PUCHAR SenseInfoBufferLength)
{
    ULONG i;
    PSRBEX_DATA SrbExData = NULL;
    BOOLEAN FoundEntry = FALSE;

    if (SrbEx->SrbFunction == SRB_FUNCTION_EXECUTE_SCSI) {
	SRBHELPER_ASSERT(SrbEx->NumSrbExData > 0);

	for (i = 0; i < SrbEx->NumSrbExData; i++) {
	    if ((SrbEx->SrbExDataOffset[i] < sizeof(STORAGE_REQUEST_BLOCK)) ||
		(SrbEx->SrbExDataOffset[i] >= SrbEx->SrbLength)) {
		SRBHELPER_ASSERT(FALSE);
		continue;
	    }

	    SrbExData = (PSRBEX_DATA)((PUCHAR)SrbEx + SrbEx->SrbExDataOffset[i]);

	    switch (SrbExData->Type) {
	    case SrbExDataTypeScsiCdb16:
		if (SrbEx->SrbExDataOffset[i] + sizeof(SRBEX_DATA_SCSI_CDB16) <=
		    SrbEx->SrbLength) {
		    FoundEntry = TRUE;
		    if (CdbLength8) {
			((PSRBEX_DATA_SCSI_CDB16)SrbExData)->CdbLength = *CdbLength8;
		    }

		    if (ScsiStatus) {
			((PSRBEX_DATA_SCSI_CDB16)SrbExData)->ScsiStatus = *ScsiStatus;
		    }

		    if (SenseInfoBuffer) {
			((PSRBEX_DATA_SCSI_CDB16)SrbExData)->SenseInfoBuffer =
			    *SenseInfoBuffer;
		    }

		    if (SenseInfoBufferLength) {
			((PSRBEX_DATA_SCSI_CDB16)SrbExData)->SenseInfoBufferLength =
			    *SenseInfoBufferLength;
		    }
		} else {
		    // Catch invalid offset
		    SRBHELPER_ASSERT(FALSE);
		}
		break;

	    case SrbExDataTypeScsiCdb32:
		if (SrbEx->SrbExDataOffset[i] + sizeof(SRBEX_DATA_SCSI_CDB32) <=
		    SrbEx->SrbLength) {
		    FoundEntry = TRUE;
		    if (CdbLength8) {
			((PSRBEX_DATA_SCSI_CDB32)SrbExData)->CdbLength = *CdbLength8;
		    }

		    if (ScsiStatus) {
			((PSRBEX_DATA_SCSI_CDB32)SrbExData)->ScsiStatus = *ScsiStatus;
		    }

		    if (SenseInfoBuffer) {
			((PSRBEX_DATA_SCSI_CDB32)SrbExData)->SenseInfoBuffer =
			    *SenseInfoBuffer;
		    }

		    if (SenseInfoBufferLength) {
			((PSRBEX_DATA_SCSI_CDB32)SrbExData)->SenseInfoBufferLength =
			    *SenseInfoBufferLength;
		    }
		} else {
		    SRBHELPER_ASSERT(FALSE);
		}
		break;

	    case SrbExDataTypeScsiCdbVar:
		if (SrbEx->SrbExDataOffset[i] + sizeof(SRBEX_DATA_SCSI_CDB_VAR) <=
		    SrbEx->SrbLength) {
		    FoundEntry = TRUE;
		    if (CdbLength32) {
			((PSRBEX_DATA_SCSI_CDB_VAR)SrbExData)->CdbLength = *CdbLength32;
		    }

		    if (ScsiStatus) {
			((PSRBEX_DATA_SCSI_CDB_VAR)SrbExData)->ScsiStatus = *ScsiStatus;
		    }

		    if (SenseInfoBuffer) {
			((PSRBEX_DATA_SCSI_CDB_VAR)SrbExData)->SenseInfoBuffer =
			    *SenseInfoBuffer;
		    }

		    if (SenseInfoBufferLength) {
			((PSRBEX_DATA_SCSI_CDB_VAR)SrbExData)->SenseInfoBufferLength =
			    *SenseInfoBufferLength;
		    }
		} else {
		    SRBHELPER_ASSERT(FALSE);
		}
		break;
	    default:
		SRBHELPER_ASSERT(FALSE);
	    }

	    if (FoundEntry) {
		break;
	    }
	}
    }
}

FORCEINLINE PCDB SrbGetCdb(IN PSTORAGE_REQUEST_BLOCK Srb)
{
    return SrbGetScsiData(Srb, NULL, NULL, NULL, NULL, NULL);
}

FORCEINLINE ULONG SrbGetSrbFunction(IN PSTORAGE_REQUEST_BLOCK Srb)
{
    return Srb->SrbFunction;
}

FORCEINLINE PVOID SrbGetSenseInfoBuffer(IN PSTORAGE_REQUEST_BLOCK Srb)
{
    PVOID pSenseInfoBuffer = NULL;
    SrbGetScsiData(Srb, NULL, NULL, NULL, &pSenseInfoBuffer, NULL);
    return pSenseInfoBuffer;
}

FORCEINLINE UCHAR SrbGetSenseInfoBufferLength(IN PSTORAGE_REQUEST_BLOCK Srb)
{
    UCHAR SenseInfoBufferLength = 0;
    SrbGetScsiData(Srb, NULL, NULL, NULL, NULL, &SenseInfoBufferLength);
    return SenseInfoBufferLength;
}

FORCEINLINE VOID SrbSetSenseInfoBuffer(IN PSTORAGE_REQUEST_BLOCK Srb,
				       IN OPTIONAL PVOID SenseInfoBuffer)
{
    SrbSetScsiData(Srb, NULL, NULL, NULL, &SenseInfoBuffer, NULL);
}

FORCEINLINE VOID SrbSetSenseInfoBufferLength(IN PSTORAGE_REQUEST_BLOCK Srb,
					     IN UCHAR SenseInfoBufferLength)
{
    SrbSetScsiData(Srb, NULL, NULL, NULL, NULL, &SenseInfoBufferLength);
}

FORCEINLINE PVOID SrbGetOriginalRequest(IN PSTORAGE_REQUEST_BLOCK Srb)
{
    return Srb->OriginalRequest;
}

FORCEINLINE VOID SrbSetOriginalRequest(IN PSTORAGE_REQUEST_BLOCK Srb,
				       IN OPTIONAL PVOID OriginalRequest)
{
    Srb->OriginalRequest = OriginalRequest;
}

FORCEINLINE PVOID SrbGetDataBuffer(IN PSTORAGE_REQUEST_BLOCK Srb)
{
    return Srb->DataBuffer;
}

FORCEINLINE VOID SrbSetDataBuffer(IN PSTORAGE_REQUEST_BLOCK Srb,
				  IN OPTIONAL PVOID DataBuffer)
{
    Srb->DataBuffer = DataBuffer;
}

FORCEINLINE ULONG SrbGetDataTransferLength(IN PSTORAGE_REQUEST_BLOCK Srb)
{
    return Srb->DataTransferLength;
}

FORCEINLINE VOID SrbSetDataTransferLength(IN PSTORAGE_REQUEST_BLOCK Srb,
					  IN ULONG DataTransferLength)
{
    Srb->DataTransferLength = DataTransferLength;
}

FORCEINLINE ULONG SrbGetTimeOutValue(IN PSTORAGE_REQUEST_BLOCK Srb)
{
    return Srb->TimeOutValue;
}

FORCEINLINE VOID SrbSetTimeOutValue(IN PSTORAGE_REQUEST_BLOCK Srb,
				    IN ULONG TimeOutValue)
{
    Srb->TimeOutValue = TimeOutValue;
}

FORCEINLINE VOID SrbSetRequestTag(IN PSTORAGE_REQUEST_BLOCK Srb,
				IN ULONG RequestTag)
{
    Srb->RequestTag = RequestTag;
}

FORCEINLINE ULONG SrbGetRequestTag(IN PSTORAGE_REQUEST_BLOCK Srb)
{
    return Srb->RequestTag;
}

FORCEINLINE PVOID SrbGetNextSrb(IN PSTORAGE_REQUEST_BLOCK Srb)
{
    return Srb->NextSrb;
}

FORCEINLINE VOID SrbSetNextSrb(IN PSTORAGE_REQUEST_BLOCK Srb,
			       IN OPTIONAL PSTORAGE_REQUEST_BLOCK NextSrb)
{
    Srb->NextSrb = NextSrb;
}

FORCEINLINE ULONG SrbGetSrbFlags(IN PSTORAGE_REQUEST_BLOCK Srb)
{
    return Srb->SrbFlags;
}

FORCEINLINE VOID SrbAssignSrbFlags(IN PSTORAGE_REQUEST_BLOCK Srb,
				   IN ULONG Flags)
{
    Srb->SrbFlags = Flags;
}

FORCEINLINE VOID SrbSetSrbFlags(IN PSTORAGE_REQUEST_BLOCK Srb,
				IN ULONG Flags)
{
    Srb->SrbFlags |= Flags;
}

FORCEINLINE VOID SrbClearSrbFlags(IN PSTORAGE_REQUEST_BLOCK Srb,
				  IN ULONG Flags)
{
    Srb->SrbFlags &= ~Flags;
}

FORCEINLINE ULONG SrbGetSystemStatus(IN PSTORAGE_REQUEST_BLOCK Srb)
{
    return Srb->SystemStatus;
}

FORCEINLINE VOID SrbSetSystemStatus(IN PSTORAGE_REQUEST_BLOCK Srb,
				    IN ULONG Status)
{
    Srb->SystemStatus = Status;
}

FORCEINLINE UCHAR SrbGetScsiStatus(IN PSTORAGE_REQUEST_BLOCK Srb)
{
    UCHAR ScsiStatus = 0;
    SrbGetScsiData(Srb, NULL, NULL, &ScsiStatus, NULL, NULL);
    return ScsiStatus;
}

FORCEINLINE VOID SrbSetScsiStatus(IN PSTORAGE_REQUEST_BLOCK Srb,
				  IN UCHAR ScsiStatus)
{
    SrbSetScsiData(Srb, NULL, NULL, &ScsiStatus, NULL, NULL);
}

FORCEINLINE UCHAR SrbGetCdbLength(IN PSTORAGE_REQUEST_BLOCK Srb)
{
    UCHAR CdbLength = 0;
    SrbGetScsiData(Srb, &CdbLength, NULL, NULL, NULL, NULL);
    return CdbLength;
}

FORCEINLINE VOID SrbSetCdbLength(IN PSTORAGE_REQUEST_BLOCK Srb,
				 IN UCHAR CdbLength)
{
    SrbSetScsiData(Srb, &CdbLength, NULL, NULL, NULL, NULL);
}

FORCEINLINE ULONG SrbGetRequestAttribute(IN PSTORAGE_REQUEST_BLOCK Srb)
{
    return Srb->RequestAttribute;
}

FORCEINLINE VOID SrbSetRequestAttribute(IN PSTORAGE_REQUEST_BLOCK Srb,
					IN UCHAR RequestAttribute)
{
    Srb->RequestAttribute = RequestAttribute;
}

FORCEINLINE UCHAR SrbGetPathId(IN PSTORAGE_REQUEST_BLOCK Srb)
{
    UCHAR PathId = 0;
    PSTOR_ADDRESS StorAddr = SrbGetAddress(Srb);
    if (StorAddr) {
	switch (StorAddr->Type) {
	case STOR_ADDRESS_TYPE_BTL8:
	    PathId = ((PSTOR_ADDR_BTL8)StorAddr)->Path;
	    break;

	default:
	    SRBHELPER_ASSERT(FALSE);
	    break;
	}
    }
    return PathId;
}

FORCEINLINE UCHAR SrbGetTargetId(IN PSTORAGE_REQUEST_BLOCK Srb)
{
    UCHAR TargetId = 0;
    PSTOR_ADDRESS StorAddr = SrbGetAddress(Srb);
    if (StorAddr) {
	switch (StorAddr->Type) {
	case STOR_ADDRESS_TYPE_BTL8:
	    TargetId = ((PSTOR_ADDR_BTL8)StorAddr)->Target;
	    break;

	default:
	    SRBHELPER_ASSERT(FALSE);
	    break;
	}
    }
    return TargetId;
}

FORCEINLINE UCHAR SrbGetLun(IN PSTORAGE_REQUEST_BLOCK Srb)
{
    UCHAR Lun = 0;
    PSTOR_ADDRESS storAddr = SrbGetAddress(Srb);
    if (storAddr) {
	switch (storAddr->Type) {
	case STOR_ADDRESS_TYPE_BTL8:
	    Lun = ((PSTOR_ADDR_BTL8)storAddr)->Lun;
	    break;

	default:
	    SRBHELPER_ASSERT(FALSE);
	    break;
	}
    }
    return Lun;
}

FORCEINLINE VOID SrbGetPathTargetLun(IN PSTORAGE_REQUEST_BLOCK Srb,
				     IN OPTIONAL PUCHAR PathId,
				     IN OPTIONAL PUCHAR TargetId,
				     IN OPTIONAL PUCHAR Lun)
{
    PSTOR_ADDRESS StorAddr = SrbGetAddress(Srb);
    if (StorAddr) {
	switch (StorAddr->Type) {
	case STOR_ADDRESS_TYPE_BTL8:
	    if (PathId != NULL) {
		*PathId = ((PSTOR_ADDR_BTL8)StorAddr)->Path;
	    }

	    if (TargetId != NULL) {
		*TargetId = ((PSTOR_ADDR_BTL8)StorAddr)->Target;
	    }

	    if (Lun != NULL) {
		*Lun = ((PSTOR_ADDR_BTL8)StorAddr)->Lun;
	    }

	    break;

	default:
	    SRBHELPER_ASSERT(FALSE);
	    break;
	}
    }
}

FORCEINLINE VOID SrbSetPathId(IN PSTORAGE_REQUEST_BLOCK Srb,
			      IN UCHAR PathId)
{
    PSTOR_ADDRESS StorAddr = SrbGetAddress(Srb);
    if (StorAddr) {
	switch (StorAddr->Type) {
	case STOR_ADDRESS_TYPE_BTL8:
	    ((PSTOR_ADDR_BTL8)StorAddr)->Path = PathId;
	    break;

	default:
	    SRBHELPER_ASSERT(FALSE);
	    break;
	}
    }
}

FORCEINLINE VOID SrbSetTargetId(IN PSTORAGE_REQUEST_BLOCK Srb,
				IN UCHAR TargetId)
{
    PSTOR_ADDRESS StorAddr = SrbGetAddress(Srb);
    if (StorAddr) {
	switch (StorAddr->Type) {
	case STOR_ADDRESS_TYPE_BTL8:
	    ((PSTOR_ADDR_BTL8)StorAddr)->Target = TargetId;
	    break;

	default:
	    SRBHELPER_ASSERT(FALSE);
	    break;
	}
    }
}

FORCEINLINE VOID SrbSetLun(IN PSTORAGE_REQUEST_BLOCK Srb,
			   IN UCHAR Lun)
{
    PSTOR_ADDRESS StorAddr = SrbGetAddress(Srb);
    if (StorAddr) {
	switch (StorAddr->Type) {
	case STOR_ADDRESS_TYPE_BTL8:
	    ((PSTOR_ADDR_BTL8)StorAddr)->Lun = Lun;
	    break;

	default:
	    SRBHELPER_ASSERT(FALSE);
	    break;
	}
    }
}

FORCEINLINE VOID SrbSetPathTargetLun(IN PSTORAGE_REQUEST_BLOCK Srb,
				     IN UCHAR PathId,
				     IN UCHAR TargetId,
				     IN UCHAR Lun)
{
    PSTOR_ADDRESS StorAddr = SrbGetAddress(Srb);
    if (StorAddr) {
	switch (StorAddr->Type) {
	case STOR_ADDRESS_TYPE_BTL8:
	    ((PSTOR_ADDR_BTL8)StorAddr)->Path = PathId;
	    ((PSTOR_ADDR_BTL8)StorAddr)->Target = TargetId;
	    ((PSTOR_ADDR_BTL8)StorAddr)->Lun = Lun;
	    break;

	default:
	    SRBHELPER_ASSERT(FALSE);
	    break;
	}
    }
}

FORCEINLINE PVOID SrbGetMiniportContext(IN PSTORAGE_REQUEST_BLOCK Srb)
{
    return Srb->MiniportContext;
}

FORCEINLINE UCHAR SrbGetSrbStatus(IN PSTORAGE_REQUEST_BLOCK Srb)
{
    return Srb->SrbStatus;
}

FORCEINLINE VOID SrbSetSrbStatus(IN PSTORAGE_REQUEST_BLOCK Srb,
				 IN UCHAR Status)
{
    if (Srb->SrbStatus & SRB_STATUS_AUTOSENSE_VALID) {
	Srb->SrbStatus = Status | SRB_STATUS_AUTOSENSE_VALID;
    } else {
	Srb->SrbStatus = Status;
    }
}

FORCEINLINE PVOID SrbGetPortContext(IN PSTORAGE_REQUEST_BLOCK Srb)
{
    return Srb->PortContext;
}

FORCEINLINE VOID SrbSetPortContext(IN PSTORAGE_REQUEST_BLOCK Srb,
				   IN PVOID PortContext)
{
    Srb->PortContext = PortContext;
}

#endif /* _SRBHELPER_H_ */
