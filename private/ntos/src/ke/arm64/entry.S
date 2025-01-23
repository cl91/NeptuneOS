#include <ntos/gen_config.h>

.section .text
.global _KiSystemStartup
_KiSystemStartup:
    mov fp, #0
    mov lr, #0

    ldr x0, =__stack_top
    mov sp, x0
    bl KiInitializeSystem

    /* Should not return */
1:  b 1b

.section .bss
.global __stack_base
.global __stack_top
__stack_base:
.align 16
.space CONFIG_NTOS_ROOT_STACK
__stack_top:
