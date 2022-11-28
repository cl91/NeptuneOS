
#include <string.h>

#pragma weak memset

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
