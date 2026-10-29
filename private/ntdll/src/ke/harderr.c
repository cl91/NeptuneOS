#include <ntdll.h>

NTSTATUS NtRaiseHardError(IN NTSTATUS ErrorStatus,
                          IN ULONG NumberOfParameters,
                          IN ULONG UnicodeStringParameterMask,
                          IN PULONG_PTR Parameters,
                          IN HARDERROR_RESPONSE_OPTION ResponseOption,
                          OUT HARDERROR_RESPONSE *Response)
{
    LOCAL_HANDLE HardErrorPort = 0;
    NtGetThreadHardErrorPort(NtCurrentThread(), &HardErrorPort);
    if (!HardErrorPort) {
	/* If the thread has hard error disabled (or the subsystem does not use
	 * hard errors), just return to caller. */
        *Response = ResponseReturnToCaller;
        return STATUS_SUCCESS;
    }

    /* Setup the LPC Message */
    UCHAR Buffer[PORT_MAXIMUM_MESSAGE_LENGTH] = {};
    PHARDERROR_MSG Message = (PHARDERROR_MSG)Buffer;
    Message->Header.TotalLength = sizeof(HARDERROR_MSG);
    Message->Header.Type = LPC_ERROR_EVENT;
    Message->Status = ErrorStatus & ~HARDERROR_OVERRIDE_ERRORMODE;
    Message->ValidResponseOptions = ResponseOption;
    Message->UnicodeStringParameterMask = UnicodeStringParameterMask;
    Message->NumberOfParameters = NumberOfParameters;
    NtQuerySystemTime(&Message->ErrorTime);

    /* Copy the parameters */
    if (Parameters) {
	RtlMoveMemory(&Message->Parameters, Parameters,
		      sizeof(ULONG_PTR) * NumberOfParameters);
    }

    NTSTATUS Status = NtRequestWaitReceivePort(HardErrorPort, &Message->Header,
					       &Message->Header, NULL);
    if (NT_SUCCESS(Status)) {
	/* Check what kind of response we got */
	if ((Message->Response != ResponseReturnToCaller) &&
	    (Message->Response != ResponseNotHandled) &&
	    (Message->Response != ResponseAbort) &&
	    (Message->Response != ResponseCancel) &&
	    (Message->Response != ResponseIgnore) &&
	    (Message->Response != ResponseNo) &&
	    (Message->Response != ResponseOk) &&
	    (Message->Response != ResponseRetry) &&
	    (Message->Response != ResponseYes) &&
	    (Message->Response != ResponseTryAgain) &&
	    (Message->Response != ResponseContinue)) {
	    /* Reset to a default one */
	    Message->Response = ResponseReturnToCaller;
	}

	/* Set the response */
	*Response = Message->Response;
    } else {
	/* Set the response */
	*Response = ResponseReturnToCaller;
    }
    return Status;
}
