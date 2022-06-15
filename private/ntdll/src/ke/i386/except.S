#include <ks386.h>

/* Note that unlike RtlRestoreContext (in amd64) this does
 * NOT modify the target stack */
.global @KiContinue@4
@KiContinue@4:
    mov CONTEXT_EIP(%ecx), %eax
    mov %eax, %fs:TebExceptionAddress
    lea CONTEXT_EDI(%ecx), %esp
    pop %edi
    pop %esi
    pop %ebx
    pop %edx
    pop %ecx
    pop %eax
    pop %ebp
    add $8, %esp
    popfd
    /* Neither pop nor jmp modifies %eflags so we are good */
    pop %esp
    jmp *%fs:TebExceptionAddress
