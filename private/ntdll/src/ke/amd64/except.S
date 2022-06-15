#include <ksamd64.h>

/* Note this is different from RtlRestoreContext because it does
 * NOT modify the target stack. */
.global KiContinue
KiContinue:
    mov CxRip(%rcx), %rax
    mov %rax, %gs:TebExceptionAddress
    lea CxRax(%rcx), %rsp
    pop %rax
    pop %rcx
    pop %rdx
    pop %rbx
    add $8, %rsp
    pop %rbp
    pop %rsi
    pop %rdi
    pop %r8
    pop %r9
    pop %r10
    pop %r11
    pop %r12
    pop %r13
    pop %r14
    pop %r15
    sub $(CxRip - CxSegGs), %rsp
    popfq
    mov (CxRsp-CxDr0)(%rsp), %rsp
    jmp *%gs:TebExceptionAddress
