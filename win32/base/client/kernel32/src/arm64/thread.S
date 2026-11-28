/*
 * COPYRIGHT:  See COPYING in the top level directory
 * PROJECT:    ReactOS system libraries
 * FILE:       dll/win32/kernel32/client/arm64/thread.S
 * PURPOSE:    Thread and process start thunks
 * PROGRAMMER:
 */

#include "../../../../../../private/rtl/inc/arm64asm.h"

.PROC BaseThreadStartupThunk
    /* BaseInitializeContext enters here with X0 containing the start routine
     * and X1 containing its parameter, which is already the ARM64 ABI for
     * BaseThreadStartup. Start with a fresh frame and tail call it. */
    mov x29, xzr
    b BaseThreadStartup
.ENDP

.PROC BaseProcessStartThunk
    /* BaseInitializeContext enters here with X0 containing the process entry
     * point, while the initial PEB parameter in X1 is unused by the process
     * startup path. */
    mov x29, xzr
    b BaseProcessStartup
.ENDP
/* EOF */
