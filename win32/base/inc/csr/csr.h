/*
 * PROJECT:     ReactOS Client/Server Runtime SubSystem
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Public definitions for CSR Clients
 * COPYRIGHT:   Copyright 2005 Alex Ionescu <alex@relsoft.net>
 *              Copyright 2012-2022 Hermès Bélusca-Maïto
 * <hermes.belusca-maito@reactos.org>
 */

#ifndef _CSR_H
#define _CSR_H

#include "csrmsg.h"

NTAPI NTSTATUS CsrClientConnectToServer(_In_ PCWSTR ObjectDirectory, _In_ ULONG ServerId,
					_In_ PVOID ConnectionInfo,
					_Inout_ PULONG ConnectionInfoSize,
					_Out_ PBOOLEAN ServerToServerCall);

NTAPI NTSTATUS CsrClientCallServer(_Inout_ PCSR_API_MESSAGE ApiMessage,
				   _Inout_opt_ PCSR_CAPTURE_BUFFER CaptureBuffer,
				   _In_ CSR_API_NUMBER ApiNumber, _In_ ULONG DataLength);

NTAPI PCSR_CAPTURE_BUFFER CsrAllocateCaptureBuffer(_In_ ULONG ArgumentCount,
						   _In_ ULONG BufferSize);

NTAPI ULONG CsrAllocateMessagePointer(_Inout_ PCSR_CAPTURE_BUFFER CaptureBuffer,
				      _In_ ULONG MessageLength,
				      _Out_ PVOID *CapturedData);

NTAPI VOID CsrCaptureMessageBuffer(_Inout_ PCSR_CAPTURE_BUFFER CaptureBuffer,
				   _In_opt_ PVOID MessageBuffer, _In_ ULONG MessageLength,
				   _Out_ PVOID *CapturedData);

NTAPI VOID CsrFreeCaptureBuffer(_In_ _Frees_ptr_ PCSR_CAPTURE_BUFFER CaptureBuffer);

NTAPI VOID CsrCaptureMessageString(_Inout_ PCSR_CAPTURE_BUFFER CaptureBuffer,
				   _In_opt_ PCSTR String, _In_ ULONG StringLength,
				   _In_ ULONG MaximumLength,
				   _Out_ PSTRING CapturedString);

NTAPI VOID CsrCaptureMessageUnicodeStringInPlace(_Inout_ PCSR_CAPTURE_BUFFER CaptureBuffer,
						 _Inout_ PUNICODE_STRING String);

NTAPI NTSTATUS
CsrCaptureMessageMultiUnicodeStringsInPlace(_Inout_ PCSR_CAPTURE_BUFFER *CaptureBuffer,
					    _In_ ULONG StringsCount,
					    _In_ PUNICODE_STRING *MessageStrings);

NTAPI PLARGE_INTEGER CsrCaptureTimeout(_In_ ULONG Milliseconds,
				       _Out_ PLARGE_INTEGER Timeout);

NTAPI VOID CsrProbeForRead(_In_ PVOID Address, _In_ ULONG Length, _In_ ULONG Alignment);

NTAPI VOID CsrProbeForWrite(_In_ PVOID Address, _In_ ULONG Length, _In_ ULONG Alignment);

NTAPI HANDLE CsrGetProcessId(VOID);

NTAPI NTSTATUS CsrNewThread(VOID);

NTAPI NTSTATUS CsrIdentifyAlertableThread(VOID);

NTAPI NTSTATUS CsrSetPriorityClass(_In_ HANDLE Process, _Inout_ PULONG PriorityClass);

#endif // _CSR_H

/* EOF */
