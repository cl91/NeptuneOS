#include <stddef.h>
#include <tchar.h>

size_t __cdecl _tcsnlen(const _TCHAR * str, size_t count)
{
    const _TCHAR *s;

    if (str == 0)
	return 0;

    for (s = str; *s && count; ++s, --count);

    return s - str;
}
