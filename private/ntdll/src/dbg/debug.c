#include <printf.h>
#include <ntdll.h>

#ifdef CONFIG_DEBUG_BUILD

VOID vDbgPrint(IN PCSTR Format, IN va_list Args)
{
    char Buf[512];
    vsnprintf(Buf, sizeof(Buf), Format, Args);
    seL4_DebugPutString(Buf);
}

NTAPI ULONG vDbgPrintEx(IN ULONG ComponentId,
			IN ULONG Level,
			IN PCCH Format,
			IN va_list VaList)
{
    vDbgPrint(Format, VaList);
    return 0;
}

ULONG DbgPrint(IN PCSTR Format, ...)
{
    va_list ArgList;
    va_start(ArgList, Format);
    vDbgPrint(Format, ArgList);
    va_end(ArgList);
    return 0;
}

ULONG DbgPrintEx(IN ULONG ComponentId,
		 IN ULONG Level,
		 IN PCSTR Format, ...)
{
    va_list ArgList;
    va_start(ArgList, Format);
    vDbgPrint(Format, ArgList);
    va_end(ArgList);
    return 0;
}

VOID _assert(PCSTR Str, PCSTR File, unsigned int Line)
{
    DbgPrint("Assertion %s failed at line %d of file %s\n",
	     Str, Line, File);
    char Buf[512];
    snprintf(Buf, sizeof(Buf), "Assertion %s failed at line %d of file %s\n",
	     Str, Line, File);
    NtDisplayStringA(Buf);
    RtlRaiseStatus(STATUS_ASSERTION_FAILURE);
}

NTAPI ULONG RtlAssert(IN PVOID FailedAssertion,
		      IN PVOID FileName,
		      IN ULONG LineNumber,
		      IN OPTIONAL PCHAR Message)
{
    DbgPrint("Assertion %s failed at line %d of file %s%s%s\n",
	     (PCSTR)FailedAssertion, LineNumber, (PCSTR)FileName,
	     Message ? ": " : "", Message ? Message : "");
    char Buf[512];
    snprintf(Buf, sizeof(Buf), "Assertion %s failed at line %d of file %s%s%s\n",
	     (PCSTR)FailedAssertion, LineNumber, (PCSTR)FileName,
	     Message ? ": " : "", Message ? Message : "");
    NtDisplayStringA(Buf);
    RtlRaiseStatus(STATUS_ASSERTION_FAILURE);
    return 0;
}

#elif defined(_MSC_VER)

VOID vDbgPrint(PCSTR Format, va_list args)
{
    /* DO nothing */
}

NTAPI ULONG vDbgPrintEx(IN ULONG ComponentId,
			IN ULONG Level,
			IN PCCH Format,
			IN va_list ap)
{
    return 0;
}

#undef DbgPrint
ULONG DbgPrint(PCSTR Format, ...)
{
    /* Do nothing */
    return 0;
}

ULONG DbgPrintEx(IN ULONG ComponentId,
		 IN ULONG Level,
		 IN PCSTR Format, ...)
{
    /* Do nothing */
    return 0;
}

VOID _assert(PCSTR str, PCSTR file, unsigned int line)
{
    /* Do nothing */
}

NTAPI ULONG RtlAssert(IN PVOID FailedAssertion,
		     IN PVOID FileName,
		     IN ULONG LineNumber,
		     IN OPTIONAL PCHAR Message)
{
    return 0;
}

#endif

#ifdef _MSC_VER

static NTAPI ULONG DebugPrompt(IN PSTRING Output, IN PSTRING Input)
{
    /* Call the Debug Service */
    return DebugService(BREAKPOINT_PROMPT, Output->Buffer, UlongToPtr(Output->Length),
			Input->Buffer, UlongToPtr(Input->MaximumLength));
}

/*
 * @implemented
 */
NTAPI ULONG DbgPrompt(IN PCCH Prompt, OUT PCH Response, IN ULONG MaximumResponseLength)
{
    STRING Output;
    STRING Input;

    /* Setup the input string */
    Input.MaximumLength = (USHORT)MaximumResponseLength;
    Input.Buffer = Response;

    /* Setup the output string */
    Output.Length = (USHORT)strlen(Prompt);
    Output.Buffer = (PCHAR)Prompt;

    /* Call the system service */
    return DebugPrompt(&Output, &Input);
}

#endif	/* _MSC_VER */

/*
 * For libsel4, required in both debug and release build.
 */
VOID __assert_fail(PCSTR Str, PCSTR File, int Line, PCSTR Function)
{
    DbgPrint("Assertion %s failed in function %s at line %d of file %s\n",
	     Str, Function, Line, File);
    /* Loop forever */
    while (1);
}

static VOID vRtlpVgaPrint(IN PCSTR Format, IN va_list Args)
{
    char Buf[512];
    vsnprintf(Buf, sizeof(Buf), Format, Args);
    NtDisplayStringA(Buf);
}

ULONG RtlpVgaPrint(IN PCSTR Format, ...)
{
    va_list ArgList;
    va_start(ArgList, Format);
    vRtlpVgaPrint(Format, ArgList);
    va_end(ArgList);
    return 0;
}
