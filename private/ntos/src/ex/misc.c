#include <ntos.h>

/*
 * TODO: Check if calling process has the required privilege
 */
NTSTATUS NtDisplayString(IN ASYNC_STATE State,
			 IN PTHREAD Thread,
			 IN PCSTR String)
{
    HalDisplayString(String);
    return STATUS_SUCCESS;
}

NTSTATUS NtSetDefaultLocale(IN ASYNC_STATE AsyncState,
                            IN PTHREAD Thread,
                            IN BOOLEAN UserProfile,
                            IN LCID DefaultLocaleId)
{
    UNIMPLEMENTED;
}

NTSTATUS NtQueryDefaultUILanguage(IN ASYNC_STATE AsyncState,
                                  IN PTHREAD Thread,
                                  OUT LANGID *LanguageId)
{
    UNIMPLEMENTED;
}

NTSTATUS NtQueryInstallUILanguage(IN ASYNC_STATE AsyncState,
                                  IN PTHREAD Thread,
                                  OUT LANGID *LanguageId)
{
    UNIMPLEMENTED;
}

NTSTATUS NtIsSystemResumeAutomatic(IN ASYNC_STATE AsyncState,
                                   IN PTHREAD Thread,
                                   OUT PBOOLEAN Automatic)
{
    UNIMPLEMENTED;
}

NTSTATUS NtSetSystemTime(IN ASYNC_STATE AsyncState,
			 IN PTHREAD Thread,
			 IN PLARGE_INTEGER SystemTime,
			 IN OPTIONAL PLARGE_INTEGER NewSystemTime)
{
    UNIMPLEMENTED;
}
