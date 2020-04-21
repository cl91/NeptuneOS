#include <nt.h>
#include <ntos.h>

/*
 * @implemented
 *
 * NOTES
 *  If source is NULL the length of source is assumed to be 0.
 */
VOID
NTAPI
RtlInitUnicodeString(
    IN OUT PUNICODE_STRING DestinationString,
    IN PCWSTR SourceString)
{
    SIZE_T Size;
    CONST SIZE_T MaxSize = (MAXUSHORT & ~1) - sizeof(UNICODE_NULL); // an even number

    if (SourceString)
    {
        Size = wcslen(SourceString) * sizeof(WCHAR);
        __analysis_assume(Size <= MaxSize);

        if (Size > MaxSize)
            Size = MaxSize;
        DestinationString->Length = (USHORT)Size;
        DestinationString->MaximumLength = (USHORT)Size + sizeof(UNICODE_NULL);
    }
    else
    {
        DestinationString->Length = 0;
        DestinationString->MaximumLength = 0;
    }

    DestinationString->Buffer = (PWCHAR)SourceString;
}

/*
 * @implemented
 */
NTSTATUS
NTAPI
RtlInitUnicodeStringEx(
    OUT PUNICODE_STRING DestinationString,
    IN PCWSTR SourceString)
{
    SIZE_T Size;
    CONST SIZE_T MaxSize = (MAXUSHORT & ~1) - sizeof(WCHAR); // an even number

    if (SourceString)
    {
        Size = wcslen(SourceString) * sizeof(WCHAR);
        if (Size > MaxSize) return STATUS_NAME_TOO_LONG;
        DestinationString->Length = (USHORT)Size;
        DestinationString->MaximumLength = (USHORT)Size + sizeof(WCHAR);
    }
    else
    {
        DestinationString->Length = 0;
        DestinationString->MaximumLength = 0;
    }

    DestinationString->Buffer = (PWCHAR)SourceString;
    return STATUS_SUCCESS;
}
