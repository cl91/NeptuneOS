.section .text
.global _start
_start:
    ldp x0, x1, [sp]
    bl LdrInitializeThunk

    /* Should not return. */
1:  b  1b
