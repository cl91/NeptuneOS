/* Copyright (C) 1994 DJ Delorie, see COPYING.DJ for details */
#include <stdlib.h>
#include <tchar.h>

/*
 * @implemented
 */
int
__cdecl
_ttoi(const _TCHAR *str)
{
  return (int)_ttoi64(str);
}
