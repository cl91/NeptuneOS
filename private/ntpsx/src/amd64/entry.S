.section .text
.global _start
_start:
    /*
     * SysV abi passes the first two parameters in rdi and rsi
     */
    mov (%rsp), %rdi
    mov 8(%rsp), %rsi
    call LdrInitializeThunk

    /* Should not return. */
1:  jmp  1b
