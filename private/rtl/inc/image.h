#include <nt.h>

#ifdef _PPC_
#define SWAPD(x) ((((x)&0xff)<<24)|(((x)&0xff00)<<8)|(((x)>>8)&0xff00)|(((x)>>24)&0xff))
#define SWAPW(x) ((((x)&0xff)<<8)|(((x)>>8)&0xff))
#define SWAPQ(x) ((SWAPD((x)&0xffffffff) << 32) | (SWAPD((x)>>32)))
#else
#define SWAPD(x) (x)
#define SWAPW(x) (x)
#define SWAPQ(x) (x)
#endif

/* From windef.h. We cannot include Win32 headers here. */
#define LOBYTE(w)	((BYTE)((DWORD_PTR)(w) & 0xff))
#define HIBYTE(w)	((BYTE)((DWORD_PTR)(w) >> 8))

#define HIWORD(l)	((WORD)(((DWORD_PTR)(l) >> 16) & 0xffff))
#define LOWORD(l)	((WORD)((DWORD_PTR)(l) & 0xffff))
#define MAKELONG(a,b)	((LONG)(((WORD)(a))|(((DWORD)((WORD)(b)))<<16)))

#define RVA(m, b)	((PVOID)((ULONG_PTR)(b) + (ULONG_PTR)(m)))

/* image.c */
NTSTATUS RtlpImageNtHeaderEx(IN ULONG Flags,
			     IN PVOID Base,
			     IN ULONG64 Size,
			     OUT PIMAGE_NT_HEADERS *OutHeaders);

PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader(IN PVOID Base);

PVOID NTAPI RtlImageDirectoryEntryToData(IN PVOID BaseAddress,
					 IN BOOLEAN MappedAsImage,
					 IN USHORT Directory,
					 IN PULONG Size);

PIMAGE_SECTION_HEADER NTAPI RtlImageRvaToSection(IN PIMAGE_NT_HEADERS NtHeader,
						 IN PVOID BaseAddress,
						 IN ULONG Rva);

PVOID NTAPI RtlImageRvaToVa(IN PIMAGE_NT_HEADERS NtHeader,
			    IN PVOID BaseAddress,
			    IN ULONG Rva,
			    IN PIMAGE_SECTION_HEADER *SectionHeader);
