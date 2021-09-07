#include <string.h>

char *strcpy(char *restrict dest, const char *restrict src)
{
    const char *restrict s = src;
    char *restrict d = dest;
    while ((*d++ = *s++));
    return dest;
}
