#pragma once

#include <nt.h>
#include <wchar.h>

VOID NTAPI RtlInitUnicodeString(IN OUT PUNICODE_STRING DestinationString,
				IN PCWSTR SourceString);

NTSTATUS NTAPI RtlInitUnicodeStringEx(OUT PUNICODE_STRING DestinationString,
				      IN PCWSTR SourceString);

NTSTATUS NTAPI RtlUnicodeToUTF8N(CHAR *utf8_dest, ULONG utf8_bytes_max,
                                 ULONG *utf8_bytes_written,
                                 const WCHAR *uni_src, ULONG uni_bytes);
