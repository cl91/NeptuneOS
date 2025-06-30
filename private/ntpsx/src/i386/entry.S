.section .text
.global _start
_start:
    /*
     * %ecx : Argument0
     * %edx : Argument1
     * cdecl pushes arguments from right to left (rightmost is pushed first)
     * gcc requires stack to be 16-byte aligned before the call
     */
    sub  $0x8, %esp
    push %edx
    push %ecx
    call LdrInitializeThunk

    /* Should not return. */
1:  jmp  1b
