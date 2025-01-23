.section .text
.global _start
_start:
    bl LdrInitializeThunk

    /* Should not return. */
1:  b  1b
