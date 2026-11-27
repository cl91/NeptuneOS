/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS Base API Server DLL
 * FILE:            subsystems/win/basesrv/api.h
 * PURPOSE:         Public server APIs definitions
 * PROGRAMMERS:     Hermes Belusca-Maito (hermes.belusca@sfr.fr)
 */

#pragma once

#include "basesrv.h"

/* appcompat.c */
CSR_API(BaseSrvCheckApplicationCompatibility);

/* dosdev.c */
VOID BaseInitDefineDosDevice(VOID);
VOID BaseCleanupDefineDosDevice(VOID);

CSR_API(BaseSrvDefineDosDevice);

/* proc.c */
CSR_API(BaseSrvGetTempFile);
CSR_API(BaseSrvCreateProcess);
CSR_API(BaseSrvCreateThread);
CSR_API(BaseSrvExitProcess);
CSR_API(BaseSrvGetProcessShutdownParam);
CSR_API(BaseSrvSetProcessShutdownParam);
CSR_API(BaseSrvDebugProcess);
CSR_API(BaseSrvRegisterThread);
CSR_API(BaseSrvSxsCreateActivationContext);
CSR_API(BaseSrvSetTermsrvAppInstallMode);
CSR_API(BaseSrvSetTermsrvClientTimeZone);

/* sndsntry.c */
CSR_API(BaseSrvSoundSentryNotification);

/* nls.c */
NTAPI VOID BaseSrvNLSInit(IN PBASE_STATIC_SERVER_DATA StaticData);

NTAPI NTSTATUS BaseSrvNlsConnect(IN PCSR_PROCESS CsrProcess,
				 IN OUT PVOID  ConnectionInfo,
				 IN OUT PULONG ConnectionInfoLength);

CSR_API(BaseSrvNlsSetUserInfo);
CSR_API(BaseSrvNlsSetMultipleUserInfo);
CSR_API(BaseSrvNlsCreateSection);
CSR_API(BaseSrvNlsUpdateCacheCount);
CSR_API(BaseSrvNlsGetUserInfo);

/* EOF */
