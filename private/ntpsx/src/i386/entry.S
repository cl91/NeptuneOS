.section .text
.global _start
_start:
    /*
     * The server sets up the correct stack alignment and pushes the
     * parameters before this entry point is entered, so we simply
     * call the C language entry point.
     */
    call LdrInitializeThunk

    /* Should not return. */
1:  jmp  1b
