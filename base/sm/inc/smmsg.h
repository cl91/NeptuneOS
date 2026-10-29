/*
 * PROJECT:     ReactOS NT-Compatible Session Manager
 * LICENSE:     BSD 2-Clause License (https://spdx.org/licenses/BSD-2-Clause)
 * PURPOSE:     SMSS Client (SB and SM) Message Format
 * COPYRIGHT:   Copyright 2012-2013 Alex Ionescu <alex.ionescu@reactos.org>
 *              Copyright 2021 Hervé Poussineau <hpoussin@reactos.org>
 *              Copyright 2022 Hermès Bélusca-Maïto <hermes.belusca-maito@reactos.org>
 */

#ifndef _SM_MSG_
#define _SM_MSG_

#pragma once

#include <nt.h>
#include <smdbg.h>

//
// There are the APIs that a Client (such as CSRSS) can send to the SMSS Server.
// These are called "SM" APIs.
//
// The exact names are not known, but we are basing them on the SmpApiName array
// in the checked build of SMSS, which is probably a close approximation. We add
// "p" to use the similar nomenclature seen/leaked out in the Base CSRSS APIs.
//
// The enumeration finishes with an enumeratee holding the maximum API number.
// Its name is based on BasepMaxApiNumber, UserpMaxApiNumber...
//
typedef enum _SMSRV_API_NUMBER {
    SmpCreateForeignSessionApi,
    SmpSessionCompleteApi,
    SmpTerminateForeignSessionApi,
    SmpExecPgmApi,
    SmpLoadDeferedSubsystemApi,
    SmpStartCsrApi,
    SmpStopCsrApi,

    SmpMaxApiNumber
} SMSRV_API_NUMBER;

//
// These are the structures making up the SM_API_MSG packet structure defined
// below. Each one corresponds to an equivalent API from the list above.
//
typedef struct _SM_CREATE_FOREIGN_SESSION_MSG {
    ULONG NotImplemented;
} SM_CREATE_FOREIGN_SESSION_MSG, *PSM_CREATE_FOREIGN_SESSION_MSG;

typedef struct _SM_SESSION_COMPLETE_MSG {
    ULONG SessionId;
    NTSTATUS SessionStatus;
} SM_SESSION_COMPLETE_MSG, *PSM_SESSION_COMPLETE_MSG;

typedef struct _SM_TERMINATE_FOREIGN_SESSION_MSG {
    ULONG NotImplemented;
} SM_TERMINATE_FOREIGN_SESSION_MSG, *PSM_TERMINATE_FOREIGN_SESSION_MSG;

typedef struct _SM_EXEC_PGM_MSG {
    RTL_USER_PROCESS_INFORMATION ProcessInformation;
    BOOLEAN DebugFlag;
} SM_EXEC_PGM_MSG, *PSM_EXEC_PGM_MSG;
#ifndef _WIN64
C_ASSERT(sizeof(SM_EXEC_PGM_MSG) == 0x48);
#else
C_ASSERT(sizeof(SM_EXEC_PGM_MSG) == 0x70);
#endif

typedef struct _SM_LOAD_DEFERED_SUBSYSTEM_MSG {
    ULONG Length;
    WCHAR Buffer[32];
} SM_LOAD_DEFERED_SUBSYSTEM_MSG, *PSM_LOAD_DEFERED_SUBSYSTEM_MSG;

typedef struct _SM_START_CSR_MSG {
    ULONG MuSessionId;
    ULONG Length;
    WCHAR Buffer[128];
    HANDLE WindowsSubSysProcessId;
    HANDLE SmpInitialCommandProcessId;
} SM_START_CSR_MSG, *PSM_START_CSR_MSG;
#ifndef _WIN64
C_ASSERT(sizeof(SM_START_CSR_MSG) == 0x110);
#else
C_ASSERT(sizeof(SM_START_CSR_MSG) == 0x118);
#endif

typedef struct _SM_STOP_CSR_MSG {
    ULONG MuSessionId;
} SM_STOP_CSR_MSG, *PSM_STOP_CSR_MSG;

//
// This is the actual packet structure sent over LPC to the \SmApiPort
//
typedef struct _SM_API_MSG {
    PORT_MESSAGE h;
    SMSRV_API_NUMBER ApiNumber;
    NTSTATUS ReturnValue;
    union {
	SM_CREATE_FOREIGN_SESSION_MSG CreateForeignSession;
	SM_SESSION_COMPLETE_MSG SessionComplete;
	SM_TERMINATE_FOREIGN_SESSION_MSG TerminateForeignComplete;
	SM_EXEC_PGM_MSG ExecPgm;
	SM_LOAD_DEFERED_SUBSYSTEM_MSG LoadDefered;
	SM_START_CSR_MSG StartCsr;
	SM_STOP_CSR_MSG StopCsr;
	SM_QUERYINFO_MSG QueryInfo;
    } u;
} SM_API_MSG, *PSM_API_MSG;

#endif // _SM_MSG_
