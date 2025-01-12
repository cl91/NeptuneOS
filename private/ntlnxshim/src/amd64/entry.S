.section .text
.global _start
_start:
    /*
     * SysV abi passes the first two parameters in rdi and rsi
     * MSCV uses rcx and rdx, so fix this up before we call the C entry point
     */
    mov %rcx, %rdi
    mov %rdx, %rsi
    call LdrInitializeThunk

    /* Should not return. */
1:  jmp  1b
