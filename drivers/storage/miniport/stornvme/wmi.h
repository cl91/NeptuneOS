/**
 *******************************************************************************
 ** Copyright (c) 2011-2012                                                   **
 **                                                                           **
 **   Integrated Device Technology, Inc.                                      **
 **   Intel Corporation                                                       **
 **   LSI Corporation                                                         **
 **                                                                           **
 ** All rights reserved.                                                      **
 **                                                                           **
 *******************************************************************************
 **                                                                           **
 ** Redistribution and use in source and binary forms, with or without        **
 ** modification, are permitted provided that the following conditions are    **
 ** met:                                                                      **
 **                                                                           **
 **   1. Redistributions of source code must retain the above copyright       **
 **      notice, this list of conditions and the following disclaimer.        **
 **                                                                           **
 **   2. Redistributions in binary form must reproduce the above copyright    **
 **      notice, this list of conditions and the following disclaimer in the  **
 **      documentation and/or other materials provided with the distribution. **
 **                                                                           **
 ** THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS   **
 ** IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, **
 ** THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR    **
 ** PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR         **
 ** CONTRIBUTORS BE LIABLE FOR ANY DIRECT,INDIRECT, INCIDENTAL, SPECIAL,      **
 ** EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,       **
 ** PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR        **
 ** PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF    **
 ** LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING      **
 ** NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS        **
 ** SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.              **
 **                                                                           **
 ** The views and conclusions contained in the software and documentation     **
 ** are those of the authors and should not be interpreted as representing    **
 ** official policies, either expressed or implied, of Intel Corporation,     **
 ** Integrated Device Technology Inc., or Sandforce Corporation.              **
 **                                                                           **
 *******************************************************************************
**/

/*
 * File: nvmeWmi.h
 */

#ifndef __NVME_WMI_H__
#define __NVME_WMI_H__

VOID DispatchWmi(IN PNVME_DEVICE_EXTENSION pHbaExtension,
		 IN PSTORAGE_REQUEST_BLOCK Srb);

VOID SpUpdateWmiRequest(IN PNVME_DEVICE_EXTENSION   pHbaExtension,
			IN PSTORAGE_REQUEST_BLOCK  pSrb,
			IN PSCSIWMI_REQUEST_CONTEXT pDispatchContext,
			IN UCHAR                    Status,
			IN ULONG                    SizeNeeded);

VOID InitializeWmiContext(IN PNVME_DEVICE_EXTENSION);

BOOLEAN HandleWmiSrb(IN     PNVME_DEVICE_EXTENSION,
		     IN OUT PSTORAGE_REQUEST_BLOCK);

NTAPI UCHAR QueryWmiRegInfo(_In_ PVOID pContext,
			    _In_ PSCSIWMI_REQUEST_CONTEXT pRequestContext,
			    _Out_ PWSTR *pMofResourceName);

NTAPI BOOLEAN QueryWmiDataBlock(_In_ PVOID pContext,
				_In_ PSCSIWMI_REQUEST_CONTEXT pDispatchContext,
				_In_ ULONG GuidIndex,
				_In_ ULONG InstanceIndex,
				_In_ ULONG InstanceCount,
				_Inout_ PULONG pInstanceLenArr,
				_In_ ULONG BufferAvail,
				_Out_writes_bytes_(BufferAvail) PUCHAR pBuffer);

NTAPI BOOLEAN ExecuteWmiMethod(_In_ PVOID pContext,
			       _In_ PSCSIWMI_REQUEST_CONTEXT pDispatchContext,
			       _In_ ULONG GuidIndex,
			       _In_ ULONG InstanceIndex,
			       _In_ ULONG MethodId,
			       _In_ ULONG InBufferSize,
			       _In_ ULONG OutBufferSize,
			       _Inout_updates_bytes_to_(InBufferSize, OutBufferSize) PUCHAR pBuffer);

#endif /* __NVME_WMI_H__ */
