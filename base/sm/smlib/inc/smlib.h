#pragma once

#include <nt.h>
#include <smmsg.h>

//
// SB Message Handler
//
typedef BOOLEAN (NTAPI *PSB_API_ROUTINE)(_In_ PSB_API_MSG SbApiMsg);

//
// The actual server functions that a client linking with SMLIB can call.
//
NTAPI NTSTATUS SmConnectToSm(_In_opt_ PCUNICODE_STRING SbApiPortName,
			     _In_opt_ LOCAL_HANDLE SbApiPort, _In_opt_ ULONG ImageType,
			     _Out_ PLOCAL_HANDLE SmApiPort);

NTAPI NTSTATUS SmSendMsgToSm(_In_ LOCAL_HANDLE SmApiPort, _Inout_ PSM_API_MSG SmApiMsg);

NTAPI NTSTATUS SmSessionComplete(_In_ LOCAL_HANDLE SmApiPort, _In_ ULONG SessionId,
				 _In_ NTSTATUS SessionStatus);

NTAPI NTSTATUS SmExecPgm(_In_ LOCAL_HANDLE SmApiPort,
			 _In_ PRTL_USER_PROCESS_INFORMATION ProcessInformation,
			 _In_ BOOLEAN DebugFlag);

NTAPI NTSTATUS SmLoadDeferedSubsystem(_In_ LOCAL_HANDLE SmApiPort,
				      _In_ PUNICODE_STRING DeferedSubsystem);

NTAPI NTSTATUS SmStartCsr(_In_ LOCAL_HANDLE SmApiPort, _Out_ PULONG pMuSessionId,
			  _In_opt_ PUNICODE_STRING CommandLine,
			  _Out_ PHANDLE pWindowsSubSysProcessId,
			  _Out_ PHANDLE pInitialCommandProcessId);

NTAPI NTSTATUS SmStopCsr(_In_ LOCAL_HANDLE SmApiPort, _In_ ULONG MuSessionId);

NTAPI NTSTATUS SmExecuteProgram(_In_ LOCAL_HANDLE SmApiPort, _In_ PUNICODE_STRING Pgm);

NTAPI NTSTATUS SmLookupSubsystem(_In_ PWSTR Name, _Out_ PWSTR Data,
				 _Inout_ PULONG DataLength, _Out_opt_ PULONG DataType,
				 _In_opt_ PVOID Environment);

NTAPI NTSTATUS SmQueryInformation(_In_ LOCAL_HANDLE SmApiPort,
				  _In_ SM_INFORMATION_CLASS SmInformationClass,
				  _Inout_ PVOID Data, _In_ ULONG DataLength,
				  _Inout_opt_ PULONG ReturnedDataLength);
