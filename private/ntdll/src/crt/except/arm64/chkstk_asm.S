#include <arm64asm.h>

#define PAGE_SIZE 4096

.PROC __chkstk
    lsl    x16, x15, #4
    mov    x17, sp
1:
    sub    x17, x17, #PAGE_SIZE
    subs   x16, x16, #PAGE_SIZE
    ldr    xzr, [x17]
    b.gt   1b
    ret
.ENDP
