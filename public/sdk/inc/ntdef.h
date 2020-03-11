#pragma once

#include <stdint.h>

#ifdef __i386__
#define _M_IX86
#endif

#ifdef __x86_64
#define _M_AMD64
#endif

#ifdef _M_IX86
#define FASTCALL __fastcall
#else
#define FASTCALL
#endif

#define NTAPI __stdcall
#define DECLSPEC_IMPORT __declspec(dllimport)
#define DECLSPEC_NORETURN   __declspec(noreturn)

/* FIXME: dllimport/dllexport */
#define NTSYSAPI
#define NTSYSCALLAPI

#undef CONST
#define CONST const
#define VOID void
typedef void *PVOID;

typedef char CHAR;
typedef unsigned char UCHAR;
typedef CHAR *PCHAR;
typedef UCHAR *PUCHAR;
typedef CONST CHAR *PCSTR;

typedef wchar_t WCHAR;
typedef WCHAR *PWCHAR, *PWSTR;

typedef short SHORT;
typedef unsigned short USHORT;
typedef SHORT *PSHORT;
typedef USHORT *PUSHORT;

typedef int32_t LONG;
typedef uint32_t ULONG;
typedef LONG *PLONG;
typedef ULONG *PULONG;

typedef PVOID HANDLE;
#define DECLARE_HANDLE(name) typedef HANDLE name
typedef HANDLE *PHANDLE;
typedef LONG HRESULT;

#define IN
#define OUT
#define OPTIONAL

typedef LONG NTSTATUS;
typedef NTSTATUS *PNTSTATUS;
#define NT_SUCCESS(Status)	(((NTSTATUS)(Status)) >= 0)
#define NT_INFORMATION(Status) (((ULONG)(Status) >> 30) == 1)
#define NT_WARNING(Status)	(((ULONG)(Status) >> 30) == 2)
#define NT_ERROR(Status)	(((ULONG)(Status) >> 30) == 3)

typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PCHAR Buffer;
} STRING, *PSTRING;

typedef struct _CSTRING
{
    USHORT Length;
    USHORT MaximumLength;
    CONST CHAR *Buffer;
} CSTRING, *PCSTRING;

typedef const UNICODE_STRING* PCUNICODE_STRING;
typedef STRING ANSI_STRING;
typedef PSTRING PANSI_STRING;
typedef STRING OEM_STRING;
typedef PSTRING POEM_STRING;
typedef CONST STRING* PCOEM_STRING;
typedef STRING CANSI_STRING;
typedef PSTRING PCANSI_STRING;
