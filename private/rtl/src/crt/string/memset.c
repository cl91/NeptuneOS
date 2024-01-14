
#include <string.h>

#ifdef _M_IX86
#pragma weak memset
#endif

void* __cdecl memset(void* src, int val, size_t count)
{
    char *char_src = (char *)src;

    while(count>0) {
        *char_src = val;
        char_src++;
        count--;
    }
    return src;
}
