#include <nt.h>

/* From windef.h. We cannot include Win32 headers here. */
#define LOBYTE(w)	((BYTE)((DWORD_PTR)(w) & 0xff))
#define HIBYTE(w)	((BYTE)((DWORD_PTR)(w) >> 8))

#define HIWORD(l)	((WORD)(((DWORD_PTR)(l) >> 16) & 0xffff))
#define LOWORD(l)	((WORD)((DWORD_PTR)(l) & 0xffff))
#define MAKELONG(a,b)	((LONG)(((WORD)(a))|(((DWORD)((WORD)(b)))<<16)))

#define RVA(m, b)	((PVOID)((ULONG_PTR)(b) + (ULONG_PTR)(m)))
