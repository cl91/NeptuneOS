#include <sel4/sel4.h>
#include <ke.h>
#include <stddef.h>

void __assert_fail(const char *str, const char *file, int line, const char *function)
{
    KeBugCheckMsg(str);
}

void KeBugCheckMsg(const char *msg)
{
    for (const char *p = msg; p != NULL && *p != '\0'; p++) {
	seL4_DebugPutChar(*p);
    }
}
