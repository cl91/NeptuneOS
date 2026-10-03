/*
 * COPYRIGHT:   See COPYING in the top level directory
 * PROJECT:     ReactOS system libraries
 * FILE:        lib/sdk/crt/string/wcstol.c
 * PURPOSE:     Unknown
 * PROGRAMER:   Unknown
 * UPDATE HISTORY:
 *              25/11/05: Added license header
 */

#include <ntdll.h>
static int
wctoint(wchar_t c)
{
  static const wchar_t zeros[] =
  {
    0x0660, 0x06f0, 0x0966, 0x09e6, 0x0a66, 0x0ae6, 0x0b66, 0x0c66, 0x0ce6,
    0x0d66, 0x0e50, 0x0ed0, 0x0f20, 0x1040, 0x17e0, 0x1810, 0xff10
  };
  unsigned int i;

  if (c >= L'0' && c <= L'9')
    return c - L'0';
  if (c >= L'A' && c <= L'Z')
    return c - L'A' + 10;
  if (c >= L'a' && c <= L'z')
    return c - L'a' + 10;
  for (i = 0; i < sizeof(zeros) / sizeof(zeros[0]) && c >= zeros[i]; i++)
    if (c <= zeros[i] + 9)
      return c - zeros[i];
  return -1;
}

/*
 * @implemented
 */
long
CDECL
wcstol(const wchar_t *nptr, wchar_t **endptr, int base)
{
  const wchar_t *s = nptr;
  long acc;
  int c;
  unsigned long cutoff;
  int neg = 0, any, cutlim;

  /*
   * Skip white space and pick up leading +/- sign if any.
   * If base is 0, allow 0x for hex and 0 for octal, else
   * assume decimal; if base is already 16, allow 0x.
   */
  do {
    c = *s++;
  } while (iswctype(c, _SPACE));
  if (c == '-')
  {
    neg = 1;
    c = *s++;
  }
  else if (c == L'+')
    c = *s++;
  if ((base == 0 || base == 16) &&
      wctoint(c) == 0 && (*s == L'x' || *s == L'X'))
  {
    c = s[1];
    s += 2;
    base = 16;
  }
  if (base == 0)
    base = wctoint(c) == 0 ? 8 : 10;

  /*
   * Compute the cutoff value between legal numbers and illegal
   * numbers.  That is the largest legal value, divided by the
   * base.  An input number that is greater than this value, if
   * followed by a legal input character, is too big.  One that
   * is equal to this value may be valid or not; the limit
   * between valid and invalid numbers is then based on the last
   * digit.  For instance, if the range for longs is
   * [-2147483648..2147483647] and the input base is 10,
   * cutoff will be set to 214748364 and cutlim to either
   * 7 (neg==0) or 8 (neg==1), meaning that if we have accumulated
   * a value > 214748364, or equal but the next digit is > 7 (or 8),
   * the number is too big, and we will return a range error.
   *
   * Set any if any `digits' consumed; make it negative to indicate
   * overflow.
   */
  cutoff = neg ? ((unsigned long)LONG_MAX+1) : LONG_MAX;
  cutlim = cutoff % (unsigned long)base;
  cutoff /= (unsigned long)base;
  for (acc = 0, any = 0;; c = *s++)
  {
    c = wctoint(c);
    if (c < 0)
      break;
    if (c >= base)
      break;
    if (any < 0 || (unsigned long)acc > cutoff || (acc == cutoff && c > cutlim))
      any = -1;
    else
    {
      any = 1;
      acc *= base;
      acc += c;
    }
  }
  if (any < 0)
  {
    acc = neg ? LONG_MIN : LONG_MAX;
  }
  else if (neg)
    acc = 0-acc;
  if (endptr != 0)
    *endptr = any ? (wchar_t *)((size_t)(s - 1)) : (wchar_t *)((size_t)nptr);
  return acc;
}
