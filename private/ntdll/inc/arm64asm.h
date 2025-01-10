#pragma once

.macro .PROC name
    .text
    .align 4
    .globl \name
    .def \name
    .scl 2
    .type 32
    .endef
    \name:
    .seh_proc \name
.endm

.macro .ENDP
    .seh_endproc
.endm
