#include <ctype.h>
#include <string.h>

static inline int __isupper(int a)
{
    return ((unsigned)(a)-'A') < 26;
}

static inline int __tolower(int c)
{
    if (__isupper(c)) return c | 32;
    return c;
}

/*
 * @implemented
 */
int _strnicmp(const char *s1, const char *s2, size_t n)
{

    if (n == 0)
	return 0;
    do {
	if (__tolower(*s1) != __tolower(*s2++))
	    return __tolower(*(unsigned const char *) s1) -
		__tolower(*(unsigned const char *) --s2);
	if (*s1++ == 0)
	    break;
    } while (--n != 0);
    return 0;
}
