#pragma once

#include <nt.h>
#include <wchar.h>

VOID NTAPI RtlInitUnicodeString(IN OUT PUNICODE_STRING DestinationString,
				IN PCWSTR SourceString);

NTSTATUS NTAPI RtlInitUnicodeStringEx(OUT PUNICODE_STRING DestinationString,
				      IN PCWSTR SourceString);
