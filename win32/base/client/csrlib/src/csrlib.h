/*
 * PROJECT:     ReactOS Client/Server Runtime SubSystem
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     CSR Client Library - Main Header
 * COPYRIGHT:   Copyright 2022 Hermès Bélusca-Maïto <hermes.belusca-maito@reactos.org>
 */

#ifndef _CSRLIB_H_
#define _CSRLIB_H_

/* INCLUDES ******************************************************************/

#include <nt.h>

/* CSRSS Client Header */
#include <csr.h>

/* GLOBALS ********************************************************************/

extern HANDLE CsrPortHeap;
extern LOCAL_HANDLE CsrCommPort;

#endif /* _CSRLIB_H_ */

/* EOF */
