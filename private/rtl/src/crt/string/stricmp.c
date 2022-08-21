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
int _stricmp(const char *s1, const char *s2)
{
  while (__tolower(*s1) == __tolower(*s2))
  {
    if (*s1 == 0)
      return 0;
    s1++;
    s2++;
  }
  return __tolower(*(unsigned const char *)s1) - __tolower(*(unsigned const char *)(s2));
}

/*
 * @implemented
 */
int _strcmpi(const char *s1, const char *s2)
{
	return _stricmp(s1,s2);
}
