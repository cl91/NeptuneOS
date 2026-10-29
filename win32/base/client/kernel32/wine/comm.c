/*
 * DEC 93 Erik Bos <erik@xs4all.nl>
 *
 * Copyright 1996 Marcus Meissner
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include <k32.h>

typedef LARGE_INTEGER PHYSICAL_ADDRESS, *PPHYSICAL_ADDRESS;
#undef SERIAL_LSRMST_ESCAPE
#undef SERIAL_LSRMST_LSR_DATA
#undef SERIAL_LSRMST_LSR_NODATA
#undef SERIAL_LSRMST_MST
#undef SERIAL_IOC_FCR_FIFO_ENABLE
#undef SERIAL_IOC_FCR_RCVR_RESET
#undef SERIAL_IOC_FCR_XMIT_RESET
#undef SERIAL_IOC_FCR_DMA_MODE
#undef SERIAL_IOC_FCR_RES1
#undef SERIAL_IOC_FCR_RES2
#undef SERIAL_IOC_FCR_RCVR_TRIGGER_LSB
#undef SERIAL_IOC_FCR_RCVR_TRIGGER_MSB
#undef SERIAL_IOC_MCR_DTR
#undef SERIAL_IOC_MCR_RTS
#undef SERIAL_IOC_MCR_OUT1
#undef SERIAL_IOC_MCR_OUT2
#undef SERIAL_IOC_MCR_LOOP
#undef IOCTL_SERIAL_LSRMST_INSERT
#include <ntddser.h>

DEBUG_CHANNEL(comm);

/***********************************************************************
 *           COMM_Parse*   (Internal)
 *
 *  The following COMM_Parse* functions are used by the BuildCommDCB
 *  functions to help parse the various parts of the device control string.
 */
static LPCWSTR COMM_ParseStart(LPCWSTR Ptr)
{
    static const WCHAR ComW[] = { 'C', 'O', 'M', 0 };

    /* The device control string may optionally start with "COMx" followed
       by an optional ':' and spaces. */
    if (!strncmpiW(Ptr, ComW, 3)) {
	Ptr += 3;

	/* Allow any com port above 0 as Win 9x does (NT only allows
	   values for com ports which are actually present) */
	if (*Ptr < '1' || *Ptr > '9')
	    return NULL;

	/* Advance pointer past port number */
	while (*Ptr >= '0' && *Ptr <= '9')
	    Ptr++;

	/* The com port number must be followed by a ':' or ' ' */
	if (*Ptr != ':' && *Ptr != ' ')
	    return NULL;

	/* Advance pointer to beginning of next parameter */
	while (*Ptr == ' ')
	    Ptr++;
	if (*Ptr == ':') {
	    Ptr++;
	    while (*Ptr == ' ')
		Ptr++;
	}
    }
    /* The device control string must not start with a space. */
    else if (*Ptr == ' ')
	return NULL;

    return Ptr;
}

static LPCWSTR COMM_ParseNumber(LPCWSTR Ptr, LPDWORD lpNumber)
{
    if (*Ptr < '0' || *Ptr > '9')
	return NULL;
    *lpNumber = strtoulW(Ptr, NULL, 10);
    while (*Ptr >= '0' && *Ptr <= '9')
	Ptr++;
    return Ptr;
}

static LPCWSTR COMM_ParseParity(LPCWSTR Ptr, LPBYTE lpParity)
{
    /* Contrary to what you might expect, Windows only sets the Parity
       member of DCB and not fParity even when parity is specified in the
       device control string */

    switch (toupperW(*Ptr++)) {
    case 'E':
	*lpParity = EVENPARITY;
	break;
    case 'M':
	*lpParity = MARKPARITY;
	break;
    case 'N':
	*lpParity = NOPARITY;
	break;
    case 'O':
	*lpParity = ODDPARITY;
	break;
    case 'S':
	*lpParity = SPACEPARITY;
	break;
    default:
	return NULL;
    }

    return Ptr;
}

static LPCWSTR COMM_ParseByteSize(LPCWSTR Ptr, LPBYTE lpByteSize)
{
    DWORD Temp;

    if (!(Ptr = COMM_ParseNumber(Ptr, &Temp)))
	return NULL;

    if (Temp >= 5 && Temp <= 8) {
	*lpByteSize = Temp;
	return Ptr;
    } else
	return NULL;
}

static LPCWSTR COMM_ParseStopBits(LPCWSTR Ptr, LPBYTE lpStopBits)
{
    DWORD Temp;
    static const WCHAR Stopbits15W[] = { '1', '.', '5', 0 };

    if (!strncmpW(Stopbits15W, Ptr, 3)) {
	Ptr += 3;
	*lpStopBits = ONE5STOPBITS;
    } else {
	if (!(Ptr = COMM_ParseNumber(Ptr, &Temp)))
	    return NULL;

	if (Temp == 1)
	    *lpStopBits = ONESTOPBIT;
	else if (Temp == 2)
	    *lpStopBits = TWOSTOPBITS;
	else
	    return NULL;
    }

    return Ptr;
}

static LPCWSTR COMM_ParseOnOff(LPCWSTR Ptr, LPDWORD lpOnoff)
{
    static const WCHAR OnW[] = { 'o', 'n', 0 };
    static const WCHAR OffW[] = { 'o', 'f', 'f', 0 };

    if (!strncmpiW(OnW, Ptr, 2)) {
	Ptr += 2;
	*lpOnoff = 1;
    } else if (!strncmpiW(OffW, Ptr, 3)) {
	Ptr += 3;
	*lpOnoff = 0;
    } else
	return NULL;

    return Ptr;
}

/***********************************************************************
 *           COMM_BuildOldCommDCB   (Internal)
 *
 *  Build a DCB using the old style settings string eg: "96,n,8,1"
 */
static BOOL COMM_BuildOldCommDCB(LPCWSTR Device, LPDCB lpDcb)
{
    WCHAR Last = 0;

    if (!(Device = COMM_ParseNumber(Device, &lpDcb->BaudRate)))
	return FALSE;

    switch (lpDcb->BaudRate) {
    case 11:
    case 30:
    case 60:
	lpDcb->BaudRate *= 10;
	break;
    case 12:
    case 24:
    case 48:
    case 96:
	lpDcb->BaudRate *= 100;
	break;
    case 19:
	lpDcb->BaudRate = 19200;
	break;
    }

    while (*Device == ' ')
	Device++;
    if (*Device++ != ',')
	return FALSE;
    while (*Device == ' ')
	Device++;

    if (!(Device = COMM_ParseParity(Device, &lpDcb->Parity)))
	return FALSE;

    while (*Device == ' ')
	Device++;
    if (*Device++ != ',')
	return FALSE;
    while (*Device == ' ')
	Device++;

    if (!(Device = COMM_ParseByteSize(Device, &lpDcb->ByteSize)))
	return FALSE;

    while (*Device == ' ')
	Device++;
    if (*Device++ != ',')
	return FALSE;
    while (*Device == ' ')
	Device++;

    if (!(Device = COMM_ParseStopBits(Device, &lpDcb->StopBits)))
	return FALSE;

    /* The last parameter for flow control is optional. */
    while (*Device == ' ')
	Device++;
    if (*Device == ',') {
	Device++;
	while (*Device == ' ')
	    Device++;
	if (*Device)
	    Last = toupperW(*Device++);
	while (*Device == ' ')
	    Device++;
    }

    /* Win NT sets the flow control members based on (or lack of) the last
       parameter.  Win 9x does not set these members. */
    switch (Last) {
    case 0:
	lpDcb->fInX = FALSE;
	lpDcb->fOutX = FALSE;
	lpDcb->fOutxCtsFlow = FALSE;
	lpDcb->fOutxDsrFlow = FALSE;
	lpDcb->fDtrControl = DTR_CONTROL_ENABLE;
	lpDcb->fRtsControl = RTS_CONTROL_ENABLE;
	break;
    case 'X':
	lpDcb->fInX = TRUE;
	lpDcb->fOutX = TRUE;
	lpDcb->fOutxCtsFlow = FALSE;
	lpDcb->fOutxDsrFlow = FALSE;
	lpDcb->fDtrControl = DTR_CONTROL_ENABLE;
	lpDcb->fRtsControl = RTS_CONTROL_ENABLE;
	break;
    case 'P':
	lpDcb->fInX = FALSE;
	lpDcb->fOutX = FALSE;
	lpDcb->fOutxCtsFlow = TRUE;
	lpDcb->fOutxDsrFlow = TRUE;
	lpDcb->fDtrControl = DTR_CONTROL_HANDSHAKE;
	lpDcb->fRtsControl = RTS_CONTROL_HANDSHAKE;
	break;
    default:
	return FALSE;
    }

    /* This should be the end of the string. */
    if (*Device)
	return FALSE;

    return TRUE;
}

/***********************************************************************
 *           COMM_BuildNewCommDCB   (Internal)
 *
 *  Build a DCB using the new style settings string.
 *   eg: "baud=9600 parity=n data=8 stop=1 xon=on to=on"
 */
static BOOL COMM_BuildNewCommDCB(LPCWSTR Device, LPDCB lpDcb, LPCOMMTIMEOUTS lpTimeouts)
{
    DWORD Temp;
    BOOL Baud = FALSE, Stop = FALSE;
    static const WCHAR BaudW[] = { 'b', 'a', 'u', 'd', '=', 0 };
    static const WCHAR ParityW[] = { 'p', 'a', 'r', 'i', 't', 'y', '=', 0 };
    static const WCHAR DataW[] = { 'd', 'a', 't', 'a', '=', 0 };
    static const WCHAR StopW[] = { 's', 't', 'o', 'p', '=', 0 };
    static const WCHAR ToW[] = { 't', 'o', '=', 0 };
    static const WCHAR XonW[] = { 'x', 'o', 'n', '=', 0 };
    static const WCHAR OdsrW[] = { 'o', 'd', 's', 'r', '=', 0 };
    static const WCHAR OctsW[] = { 'o', 'c', 't', 's', '=', 0 };
    static const WCHAR DtrW[] = { 'd', 't', 'r', '=', 0 };
    static const WCHAR RtsW[] = { 'r', 't', 's', '=', 0 };
    static const WCHAR IdsrW[] = { 'i', 'd', 's', 'r', '=', 0 };

    while (*Device) {
	while (*Device == ' ')
	    Device++;

	if (!strncmpiW(BaudW, Device, 5)) {
	    Baud = TRUE;

	    if (!(Device = COMM_ParseNumber(Device + 5, &lpDcb->BaudRate)))
		return FALSE;
	} else if (!strncmpiW(ParityW, Device, 7)) {
	    if (!(Device = COMM_ParseParity(Device + 7, &lpDcb->Parity)))
		return FALSE;
	} else if (!strncmpiW(DataW, Device, 5)) {
	    if (!(Device = COMM_ParseByteSize(Device + 5, &lpDcb->ByteSize)))
		return FALSE;
	} else if (!strncmpiW(StopW, Device, 5)) {
	    Stop = TRUE;

	    if (!(Device = COMM_ParseStopBits(Device + 5, &lpDcb->StopBits)))
		return FALSE;
	} else if (!strncmpiW(ToW, Device, 3)) {
	    if (!(Device = COMM_ParseOnOff(Device + 3, &Temp)))
		return FALSE;

	    lpTimeouts->ReadIntervalTimeout = 0;
	    lpTimeouts->ReadTotalTimeoutMultiplier = 0;
	    lpTimeouts->ReadTotalTimeoutConstant = 0;
	    lpTimeouts->WriteTotalTimeoutMultiplier = 0;
	    lpTimeouts->WriteTotalTimeoutConstant = Temp ? 60000 : 0;
	} else if (!strncmpiW(XonW, Device, 4)) {
	    if (!(Device = COMM_ParseOnOff(Device + 4, &Temp)))
		return FALSE;

	    lpDcb->fOutX = Temp;
	    lpDcb->fInX = Temp;
	} else if (!strncmpiW(OdsrW, Device, 5)) {
	    if (!(Device = COMM_ParseOnOff(Device + 5, &Temp)))
		return FALSE;

	    lpDcb->fOutxDsrFlow = Temp;
	} else if (!strncmpiW(OctsW, Device, 5)) {
	    if (!(Device = COMM_ParseOnOff(Device + 5, &Temp)))
		return FALSE;

	    lpDcb->fOutxCtsFlow = Temp;
	} else if (!strncmpiW(DtrW, Device, 4)) {
	    if (!(Device = COMM_ParseOnOff(Device + 4, &Temp)))
		return FALSE;

	    lpDcb->fDtrControl = Temp;
	} else if (!strncmpiW(RtsW, Device, 4)) {
	    if (!(Device = COMM_ParseOnOff(Device + 4, &Temp)))
		return FALSE;

	    lpDcb->fRtsControl = Temp;
	} else if (!strncmpiW(IdsrW, Device, 5)) {
	    if (!(Device = COMM_ParseOnOff(Device + 5, &Temp)))
		return FALSE;

	    /* Win NT sets the fDsrSensitivity member based on the
	       idsr parameter.  Win 9x sets fOutxDsrFlow instead. */
	    lpDcb->fDsrSensitivity = Temp;
	} else
	    return FALSE;

	/* After the above parsing, the next character (if not the end of
	   the string) should be a space */
	if (*Device && *Device != ' ')
	    return FALSE;
    }

    /* If stop bits were not specified, a default is always supplied. */
    if (!Stop) {
	if (Baud && lpDcb->BaudRate == 110)
	    lpDcb->StopBits = TWOSTOPBITS;
	else
	    lpDcb->StopBits = ONESTOPBIT;
    }

    return TRUE;
}

/**************************************************************************
 *         BuildCommDCBA		(KERNEL32.@)
 *
 *  Updates a device control block data structure with values from an
 *  ascii device control string.  The device control string has two forms
 *  normal and extended, it must be exclusively in one or the other form.
 *
 * RETURNS
 *
 *  True on success, false on a malformed control string.
 */
WINAPI BOOL BuildCommDCBA(LPCSTR Device, /* [in] The ascii device control string used to
					    update the DCB. */
			  LPDCB lpDcb) /* [out] The device control block to be updated. */
{
    return BuildCommDCBAndTimeoutsA(Device, lpDcb, NULL);
}

/**************************************************************************
 *         BuildCommDCBAndTimeoutsA		(KERNEL32.@)
 *
 *  Updates a device control block data structure with values from an
 *  ascii device control string.  Taking timeout values from a timeouts
 *  struct if desired by the control string.
 *
 * RETURNS
 *
 *  True on success, false bad handles etc.
 */
WINAPI BOOL BuildCommDCBAndTimeoutsA(LPCSTR Device, /* [in] The ascii device control
						       string. */
				     LPDCB lpDcb, /* [out] The device control block to be
						     updated. */
				     LPCOMMTIMEOUTS lpTimeouts) /* [in] The COMMTIMEOUTS
								   structure to be
								   updated. */
{
    BOOL Ret = FALSE;
    UNICODE_STRING DeviceW;

    TRACE("(%s,%p,%p)\n", Device, lpDcb, lpTimeouts);
    if (Device)
	RtlCreateUnicodeStringFromAsciiz(&DeviceW, Device);
    else
	DeviceW.Buffer = NULL;

    if (DeviceW.Buffer)
	Ret = BuildCommDCBAndTimeoutsW(DeviceW.Buffer, lpDcb, lpTimeouts);

    RtlFreeUnicodeString(&DeviceW);
    return Ret;
}

/**************************************************************************
 *         BuildCommDCBAndTimeoutsW	(KERNEL32.@)
 *
 *  Updates a device control block data structure with values from a
 *  unicode device control string.  Taking timeout values from a timeouts
 *  struct if desired by the control string.
 *
 * RETURNS
 *
 *  True on success, false bad handles etc
 */
WINAPI BOOL BuildCommDCBAndTimeoutsW(LPCWSTR Devid, /* [in] The unicode device control
						       string. */
				     LPDCB lpDcb, /* [out] The device control block to be
						     updated. */
				     LPCOMMTIMEOUTS lpTimeouts) /* [in] The COMMTIMEOUTS
								   structure to be
								   updated. */
{
    DCB Dcb;
    COMMTIMEOUTS Timeouts;
    BOOL Result;
    LPCWSTR Ptr = Devid;

    TRACE("(%ws,%p,%p)\n", Devid, lpDcb, lpTimeouts);

    memset(&Timeouts, 0, sizeof Timeouts);

    /* Set DCBlength. (Windows NT does not do this, but 9x does) */
    lpDcb->DCBlength = sizeof(DCB);

    /* Make a copy of the original data structures to work with since if
       if there is an error in the device control string the originals
       should not be modified (except possibly DCBlength) */
    Dcb = *lpDcb;
    if (lpTimeouts)
	Timeouts = *lpTimeouts;

    Ptr = COMM_ParseStart(Ptr);

    if (Ptr == NULL)
	Result = FALSE;
    else if (strchrW(Ptr, ','))
	Result = COMM_BuildOldCommDCB(Ptr, &Dcb);
    else
	Result = COMM_BuildNewCommDCB(Ptr, &Dcb, &Timeouts);

    if (Result) {
	*lpDcb = Dcb;
	if (lpTimeouts)
	    *lpTimeouts = Timeouts;
	return TRUE;
    } else {
	WARN("Invalid device control string: %ws\n", Devid);
	SetLastError(ERROR_INVALID_PARAMETER);
	return FALSE;
    }
}

/**************************************************************************
 *         BuildCommDCBW		(KERNEL32.@)
 *
 *  Updates a device control block structure with values from an
 *  unicode device control string.  The device control string has two forms
 *  normal and extended, it must be exclusively in one or the other form.
 *
 * RETURNS
 *
 *  True on success, false on a malformed control string.
 */
WINAPI BOOL BuildCommDCBW(LPCWSTR Devid, /* [in] The unicode device control string. */
			  LPDCB lpDcb) /* [out] The device control block to be updated. */
{
    return BuildCommDCBAndTimeoutsW(Devid, lpDcb, NULL);
}

/*****************************************************************************
 *	SetCommBreak		(KERNEL32.@)
 *
 *  Halts the transmission of characters to a communications device.
 *
 * PARAMS
 *      handle  [in] The communications device to suspend
 *
 * RETURNS
 *
 *  True on success, and false if the communications device could not be found,
 *  the control is not supported.
 *
 * BUGS
 *
 *  Only TIOCSBRK and TIOCCBRK are supported.
 */
WINAPI BOOL SetCommBreak(HANDLE Handle)
{
    DWORD dwBytesReturned;
    return DeviceIoControl(Handle, IOCTL_SERIAL_SET_BREAK_ON, NULL, 0, NULL, 0,
			   &dwBytesReturned, NULL);
}

/*****************************************************************************
 *	ClearCommBreak		(KERNEL32.@)
 *
 *  Resumes character transmission from a communication device.
 *
 * PARAMS
 *
 *      handle [in] The halted communication device whose character transmission is to be
 * resumed
 *
 * RETURNS
 *
 *  True on success and false if the communications device could not be found.
 *
 * BUGS
 *
 *  Only TIOCSBRK and TIOCCBRK are supported.
 */
WINAPI BOOL ClearCommBreak(HANDLE Handle)
{
    DWORD dwBytesReturned;
    return DeviceIoControl(Handle, IOCTL_SERIAL_SET_BREAK_OFF, NULL, 0, NULL, 0,
			   &dwBytesReturned, NULL);
}

/*****************************************************************************
 *	EscapeCommFunction	(KERNEL32.@)
 *
 *  Directs a communication device to perform an extended function.
 *
 * PARAMS
 *
 *      handle          [in] The communication device to perform the extended function
 *      nFunction       [in] The extended function to be performed
 *
 * RETURNS
 *
 *  True or requested data on successful completion of the command,
 *  false if the device is not present cannot execute the command
 *  or the command failed.
 */
WINAPI BOOL EscapeCommFunction(HANDLE Handle, DWORD Func)
{
    DWORD Ioc;
    DWORD dwBytesReturned;

    switch (Func) {
    case CLRDTR:
	Ioc = IOCTL_SERIAL_CLR_DTR;
	break;
    case CLRRTS:
	Ioc = IOCTL_SERIAL_CLR_RTS;
	break;
    case SETDTR:
	Ioc = IOCTL_SERIAL_SET_DTR;
	break;
    case SETRTS:
	Ioc = IOCTL_SERIAL_SET_RTS;
	break;
    case SETXOFF:
	Ioc = IOCTL_SERIAL_SET_XOFF;
	break;
    case SETXON:
	Ioc = IOCTL_SERIAL_SET_XON;
	break;
    case SETBREAK:
	Ioc = IOCTL_SERIAL_SET_BREAK_ON;
	break;
    case CLRBREAK:
	Ioc = IOCTL_SERIAL_SET_BREAK_OFF;
	break;
    case RESETDEV:
	Ioc = IOCTL_SERIAL_RESET_DEVICE;
	break;
    default:
	ERR("Unknown function code (%u)\n", Func);
	SetLastError(ERROR_INVALID_PARAMETER);
	return FALSE;
    }
    return DeviceIoControl(Handle, Ioc, NULL, 0, NULL, 0, &dwBytesReturned, NULL);
}

/********************************************************************
 *      PurgeComm        (KERNEL32.@)
 *
 *  Terminates pending operations and/or discards buffers on a
 *  communication resource.
 *
 * PARAMS
 *
 *      handle  [in] The communication resource to be purged
 *      flags   [in] Flags for clear pending/buffer on input/output
 *
 * RETURNS
 *
 *  True on success and false if the communications handle is bad.
 */
WINAPI BOOL PurgeComm(HANDLE Handle, DWORD Flags)
{
    DWORD dwBytesReturned;
    return DeviceIoControl(Handle, IOCTL_SERIAL_PURGE, &Flags, sizeof(Flags), NULL, 0,
			   &dwBytesReturned, NULL);
}

/*****************************************************************************
 *	ClearCommError	(KERNEL32.@)
 *
 *  Enables further I/O operations on a communications resource after
 *  supplying error and current status information.
 *
 * PARAMS
 *
 *      handle  [in]    The communication resource with the error
 *      errors  [out]   Flags indicating error the resource experienced
 *      lpStat  [out] The status of the communication resource
 * RETURNS
 *
 *  True on success, false if the communication resource handle is bad.
 */
WINAPI BOOL ClearCommError(HANDLE Handle, LPDWORD Errors, LPCOMSTAT lpStat)
{
    SERIAL_STATUS Status;
    DWORD dwBytesReturned;

    if (!DeviceIoControl(Handle, IOCTL_SERIAL_GET_COMMSTATUS, NULL, 0, &Status,
			 sizeof(Status), &dwBytesReturned, NULL))
	return FALSE;

    if (Errors) {
	*Errors = 0;
	if (Status.Errors & SERIAL_ERROR_BREAK)
	    *Errors |= CE_BREAK;
	if (Status.Errors & SERIAL_ERROR_FRAMING)
	    *Errors |= CE_FRAME;
	if (Status.Errors & SERIAL_ERROR_OVERRUN)
	    *Errors |= CE_OVERRUN;
	if (Status.Errors & SERIAL_ERROR_QUEUEOVERRUN)
	    *Errors |= CE_RXOVER;
	if (Status.Errors & SERIAL_ERROR_PARITY)
	    *Errors |= CE_RXPARITY;
    }

    if (lpStat) {
	memset(lpStat, 0, sizeof(*lpStat));

	if (Status.HoldReasons & SERIAL_TX_WAITING_FOR_CTS)
	    lpStat->fCtsHold = TRUE;
	if (Status.HoldReasons & SERIAL_TX_WAITING_FOR_DSR)
	    lpStat->fDsrHold = TRUE;
	if (Status.HoldReasons & SERIAL_TX_WAITING_FOR_DCD)
	    lpStat->fRlsdHold = TRUE;
	if (Status.HoldReasons & SERIAL_TX_WAITING_FOR_XON)
	    lpStat->fXoffHold = TRUE;
	if (Status.HoldReasons & SERIAL_TX_WAITING_XOFF_SENT)
	    lpStat->fXoffSent = TRUE;
	if (Status.EofReceived)
	    lpStat->fEof = TRUE;
	if (Status.WaitForImmediate)
	    lpStat->fTxim = TRUE;
	lpStat->cbInQue = Status.AmountInInQueue;
	lpStat->cbOutQue = Status.AmountInOutQueue;
    }
    return TRUE;
}

/*****************************************************************************
 *      SetupComm       (KERNEL32.@)
 *
 *  Called after CreateFile to hint to the communication resource to use
 *  specified sizes for input and output buffers rather than the default values.
 *
 * PARAMS
 *      handle  [in]    The just created communication resource handle
 *      insize  [in]    The suggested size of the communication resources input buffer in
 * bytes outsize [in]    The suggested size of the communication resources output buffer
 * in bytes
 *
 * RETURNS
 *
 *  True if successful, false if the communications resource handle is bad.
 *
 * BUGS
 *
 *  Stub.
 */
WINAPI BOOL SetupComm(HANDLE Handle, DWORD Insize, DWORD Outsize)
{
    SERIAL_QUEUE_SIZE Sqs;
    DWORD dwBytesReturned;

    Sqs.InSize = Insize;
    Sqs.OutSize = Outsize;
    return DeviceIoControl(Handle, IOCTL_SERIAL_SET_QUEUE_SIZE, &Sqs, sizeof(Sqs), NULL,
			   0, &dwBytesReturned, NULL);
}

/*****************************************************************************
 *	GetCommMask	(KERNEL32.@)
 *
 *  Obtain the events associated with a communication device that will cause
 *  a call WaitCommEvent to return.
 *
 *  PARAMS
 *
 *      handle  [in]    The communications device
 *      evtmask [out]   The events which cause WaitCommEvent to return
 *
 *  RETURNS
 *
 *   True on success, fail on bad device handle etc.
 */
WINAPI BOOL GetCommMask(HANDLE Handle, LPDWORD Evtmask)
{
    DWORD dwBytesReturned;
    TRACE("handle %p, mask %p\n", Handle, Evtmask);
    return DeviceIoControl(Handle, IOCTL_SERIAL_GET_WAIT_MASK, NULL, 0, Evtmask,
			   sizeof(*Evtmask), &dwBytesReturned, NULL);
}

/*****************************************************************************
 *	SetCommMask	(KERNEL32.@)
 *
 *  There be some things we need to hear about yon there communications device.
 *  (Set which events associated with a communication device should cause
 *  a call WaitCommEvent to return.)
 *
 * PARAMS
 *
 *      handle  [in]    The communications device
 *      evtmask [in]    The events that are to be monitored
 *
 * RETURNS
 *
 *  True on success, false on bad handle etc.
 */
WINAPI BOOL SetCommMask(HANDLE Handle, DWORD Evtmask)
{
    DWORD dwBytesReturned;
    TRACE("handle %p, mask %x\n", Handle, Evtmask);
    return DeviceIoControl(Handle, IOCTL_SERIAL_SET_WAIT_MASK, &Evtmask, sizeof(Evtmask),
			   NULL, 0, &dwBytesReturned, NULL);
}

static void DumpDcb(const DCB *lpDcb)
{
    TRACE("bytesize=%d baudrate=%d fParity=%d Parity=%d stopbits=%d\n", lpDcb->ByteSize,
	  lpDcb->BaudRate, lpDcb->fParity, lpDcb->Parity,
	  (lpDcb->StopBits == ONESTOPBIT)  ? 1 :
	  (lpDcb->StopBits == TWOSTOPBITS) ? 2 :
					     0);
    TRACE("%sIXON %sIXOFF\n", (lpDcb->fOutX) ? "" : "~", (lpDcb->fInX) ? "" : "~");
    TRACE("fOutxCtsFlow=%d fRtsControl=%d\n", lpDcb->fOutxCtsFlow, lpDcb->fRtsControl);
    TRACE("fOutxDsrFlow=%d fDtrControl=%d\n", lpDcb->fOutxDsrFlow, lpDcb->fDtrControl);
    if (lpDcb->fOutxCtsFlow || lpDcb->fRtsControl == RTS_CONTROL_HANDSHAKE)
	TRACE("CRTSCTS\n");
    else
	TRACE("~CRTSCTS\n");
}

/*****************************************************************************
 *	SetCommState    (KERNEL32.@)
 *
 *  Re-initializes all hardware and control settings of a communications device,
 *  with values from a device control block without affecting the input and output
 *  queues.
 *
 * PARAMS
 *
 *      handle  [in]    The communications device
 *      lpdcb   [out]   The device control block
 *
 * RETURNS
 *
 *  True on success, false on failure, e.g., if the XonChar is equal to the XoffChar.
 */
WINAPI BOOL SetCommState(HANDLE Handle, LPDCB lpDcb)
{
    SERIAL_BAUD_RATE Sbr;
    SERIAL_LINE_CONTROL Slc;
    SERIAL_HANDFLOW Shf;
    SERIAL_CHARS Sc;
    DWORD dwBytesReturned;

    TRACE("handle %p, ptr %p\n", Handle, lpDcb);

    if (lpDcb == NULL) {
	SetLastError(ERROR_INVALID_PARAMETER);
	return FALSE;
    }
    DumpDcb(lpDcb);

    Sbr.BaudRate = lpDcb->BaudRate;

    Slc.StopBits = lpDcb->StopBits;
    Slc.Parity = lpDcb->Parity;
    Slc.WordLength = lpDcb->ByteSize;

    Shf.ControlHandShake = 0;
    Shf.FlowReplace = 0;
    if (lpDcb->fOutxCtsFlow)
	Shf.ControlHandShake |= SERIAL_CTS_HANDSHAKE;
    if (lpDcb->fOutxDsrFlow)
	Shf.ControlHandShake |= SERIAL_DSR_HANDSHAKE;
    switch (lpDcb->fDtrControl) {
    case DTR_CONTROL_DISABLE:
	break;
    case DTR_CONTROL_ENABLE:
	Shf.ControlHandShake |= SERIAL_DTR_CONTROL;
	break;
    case DTR_CONTROL_HANDSHAKE:
	Shf.ControlHandShake |= SERIAL_DTR_HANDSHAKE;
	break;
    default:
	SetLastError(ERROR_INVALID_PARAMETER);
	return FALSE;
    }
    switch (lpDcb->fRtsControl) {
    case RTS_CONTROL_DISABLE:
	break;
    case RTS_CONTROL_ENABLE:
	Shf.FlowReplace |= SERIAL_RTS_CONTROL;
	break;
    case RTS_CONTROL_HANDSHAKE:
	Shf.FlowReplace |= SERIAL_RTS_HANDSHAKE;
	break;
    case RTS_CONTROL_TOGGLE:
	Shf.FlowReplace |= SERIAL_RTS_CONTROL | SERIAL_RTS_HANDSHAKE;
	break;
    default:
	SetLastError(ERROR_INVALID_PARAMETER);
	return FALSE;
    }
    if (lpDcb->fDsrSensitivity)
	Shf.ControlHandShake |= SERIAL_DSR_SENSITIVITY;
    if (lpDcb->fAbortOnError)
	Shf.ControlHandShake |= SERIAL_ERROR_ABORT;

    if (lpDcb->fErrorChar)
	Shf.FlowReplace |= SERIAL_ERROR_CHAR;
    if (lpDcb->fNull)
	Shf.FlowReplace |= SERIAL_NULL_STRIPPING;
    if (lpDcb->fTXContinueOnXoff)
	Shf.FlowReplace |= SERIAL_XOFF_CONTINUE;
    if (lpDcb->fOutX)
	Shf.FlowReplace |= SERIAL_AUTO_TRANSMIT;
    if (lpDcb->fInX)
	Shf.FlowReplace |= SERIAL_AUTO_RECEIVE;

    Shf.XonLimit = lpDcb->XonLim;
    Shf.XoffLimit = lpDcb->XoffLim;

    Sc.EofChar = lpDcb->EofChar;
    Sc.ErrorChar = lpDcb->ErrorChar;
    Sc.BreakChar = 0;
    Sc.EventChar = lpDcb->EvtChar;
    Sc.XonChar = lpDcb->XonChar;
    Sc.XoffChar = lpDcb->XoffChar;

    /* note: change DTR/RTS lines after setting the comm attributes,
     * so flow control does not interfere.
     */
    return (DeviceIoControl(Handle, IOCTL_SERIAL_SET_BAUD_RATE, &Sbr, sizeof(Sbr), NULL,
			    0, &dwBytesReturned, NULL) &&
	    DeviceIoControl(Handle, IOCTL_SERIAL_SET_LINE_CONTROL, &Slc, sizeof(Slc),
			    NULL, 0, &dwBytesReturned, NULL) &&
	    DeviceIoControl(Handle, IOCTL_SERIAL_SET_HANDFLOW, &Shf, sizeof(Shf), NULL, 0,
			    &dwBytesReturned, NULL) &&
	    DeviceIoControl(Handle, IOCTL_SERIAL_SET_CHARS, &Sc, sizeof(Sc), NULL, 0,
			    &dwBytesReturned, NULL));
}

/*****************************************************************************
 *	GetCommState	(KERNEL32.@)
 *
 *  Fills in a device control block with information from a communications device.
 *
 * PARAMS
 *      handle          [in]    The communications device
 *      lpdcb           [out]   The device control block
 *
 * RETURNS
 *
 *  True on success, false if the communication device handle is bad etc
 *
 * BUGS
 *
 *  XonChar and XoffChar are not set.
 */
WINAPI BOOL GetCommState(HANDLE Handle, LPDCB lpDcb)
{
    SERIAL_BAUD_RATE Sbr;
    SERIAL_LINE_CONTROL Slc;
    SERIAL_HANDFLOW Shf;
    SERIAL_CHARS Sc;
    DWORD dwBytesReturned;

    TRACE("handle %p, ptr %p\n", Handle, lpDcb);

    if (!lpDcb) {
	SetLastError(ERROR_INVALID_PARAMETER);
	return FALSE;
    }

    if (!DeviceIoControl(Handle, IOCTL_SERIAL_GET_BAUD_RATE, NULL, 0, &Sbr, sizeof(Sbr),
			 &dwBytesReturned, NULL) ||
	!DeviceIoControl(Handle, IOCTL_SERIAL_GET_LINE_CONTROL, NULL, 0, &Slc,
			 sizeof(Slc), &dwBytesReturned, NULL) ||
	!DeviceIoControl(Handle, IOCTL_SERIAL_GET_HANDFLOW, NULL, 0, &Shf, sizeof(Shf),
			 &dwBytesReturned, NULL) ||
	!DeviceIoControl(Handle, IOCTL_SERIAL_GET_CHARS, NULL, 0, &Sc, sizeof(Sc),
			 &dwBytesReturned, NULL))
	return FALSE;

    memset(lpDcb, 0, sizeof(*lpDcb));
    lpDcb->DCBlength = sizeof(*lpDcb);

    /* yes, they seem no never be (re)set on NT */
    lpDcb->fBinary = 1;
    lpDcb->fParity = 0;

    lpDcb->BaudRate = Sbr.BaudRate;

    lpDcb->StopBits = Slc.StopBits;
    lpDcb->Parity = Slc.Parity;
    lpDcb->ByteSize = Slc.WordLength;

    if (Shf.ControlHandShake & SERIAL_CTS_HANDSHAKE)
	lpDcb->fOutxCtsFlow = 1;
    if (Shf.ControlHandShake & SERIAL_DSR_HANDSHAKE)
	lpDcb->fOutxDsrFlow = 1;
    switch (Shf.ControlHandShake & (SERIAL_DTR_CONTROL | SERIAL_DTR_HANDSHAKE)) {
    case 0:
	lpDcb->fDtrControl = DTR_CONTROL_DISABLE;
	break;
    case SERIAL_DTR_CONTROL:
	lpDcb->fDtrControl = DTR_CONTROL_ENABLE;
	break;
    case SERIAL_DTR_HANDSHAKE:
	lpDcb->fDtrControl = DTR_CONTROL_HANDSHAKE;
	break;
    }
    switch (Shf.FlowReplace & (SERIAL_RTS_CONTROL | SERIAL_RTS_HANDSHAKE)) {
    case 0:
	lpDcb->fRtsControl = RTS_CONTROL_DISABLE;
	break;
    case SERIAL_RTS_CONTROL:
	lpDcb->fRtsControl = RTS_CONTROL_ENABLE;
	break;
    case SERIAL_RTS_HANDSHAKE:
	lpDcb->fRtsControl = RTS_CONTROL_HANDSHAKE;
	break;
    case SERIAL_RTS_CONTROL | SERIAL_RTS_HANDSHAKE:
	lpDcb->fRtsControl = RTS_CONTROL_TOGGLE;
	break;
    }
    if (Shf.ControlHandShake & SERIAL_DSR_SENSITIVITY)
	lpDcb->fDsrSensitivity = 1;
    if (Shf.ControlHandShake & SERIAL_ERROR_ABORT)
	lpDcb->fAbortOnError = 1;
    if (Shf.FlowReplace & SERIAL_ERROR_CHAR)
	lpDcb->fErrorChar = 1;
    if (Shf.FlowReplace & SERIAL_NULL_STRIPPING)
	lpDcb->fNull = 1;
    if (Shf.FlowReplace & SERIAL_XOFF_CONTINUE)
	lpDcb->fTXContinueOnXoff = 1;
    lpDcb->XonLim = Shf.XonLimit;
    lpDcb->XoffLim = Shf.XoffLimit;

    if (Shf.FlowReplace & SERIAL_AUTO_TRANSMIT)
	lpDcb->fOutX = 1;
    if (Shf.FlowReplace & SERIAL_AUTO_RECEIVE)
	lpDcb->fInX = 1;

    lpDcb->EofChar = Sc.EofChar;
    lpDcb->ErrorChar = Sc.ErrorChar;
    lpDcb->EvtChar = Sc.EventChar;
    lpDcb->XonChar = Sc.XonChar;
    lpDcb->XoffChar = Sc.XoffChar;

    TRACE("OK\n");
    DumpDcb(lpDcb);

    return TRUE;
}

/*****************************************************************************
 *	TransmitCommChar	(KERNEL32.@)
 *
 *  Transmits a single character in front of any pending characters in the
 *  output buffer.  Usually used to send an interrupt character to a host.
 *
 * PARAMS
 *      hComm           [in]    The communication device in need of a command character
 *      chTransmit      [in]    The character to transmit
 *
 * RETURNS
 *
 *  True if the call succeeded, false if the previous command character to the
 *  same device has not been sent yet the handle is bad etc.
 *
 */
WINAPI BOOL TransmitCommChar(HANDLE hComm, CHAR chTransmit)
{
    DWORD dwBytesReturned;
    return DeviceIoControl(hComm, IOCTL_SERIAL_IMMEDIATE_CHAR, &chTransmit,
			   sizeof(chTransmit), NULL, 0, &dwBytesReturned, NULL);
}

/*****************************************************************************
 *	GetCommTimeouts		(KERNEL32.@)
 *
 *  Obtains the request timeout values for the communications device.
 *
 * PARAMS
 *      hComm           [in]    The communications device
 *      lptimeouts      [out]   The struct of request timeouts
 *
 * RETURNS
 *
 *  True on success, false if communications device handle is bad
 *  or the target structure is null.
 */
WINAPI BOOL GetCommTimeouts(HANDLE hComm, LPCOMMTIMEOUTS lpTimeouts)
{
    SERIAL_TIMEOUTS St;
    DWORD dwBytesReturned;

    TRACE("(%p, %p)\n", hComm, lpTimeouts);
    if (!lpTimeouts) {
	SetLastError(ERROR_INVALID_PARAMETER);
	return FALSE;
    }
    if (!DeviceIoControl(hComm, IOCTL_SERIAL_GET_TIMEOUTS, NULL, 0, &St, sizeof(St),
			 &dwBytesReturned, NULL))
	return FALSE;
    lpTimeouts->ReadIntervalTimeout = St.ReadIntervalTimeout;
    lpTimeouts->ReadTotalTimeoutMultiplier = St.ReadTotalTimeoutMultiplier;
    lpTimeouts->ReadTotalTimeoutConstant = St.ReadTotalTimeoutConstant;
    lpTimeouts->WriteTotalTimeoutMultiplier = St.WriteTotalTimeoutMultiplier;
    lpTimeouts->WriteTotalTimeoutConstant = St.WriteTotalTimeoutConstant;
    return TRUE;
}

/*****************************************************************************
 *	SetCommTimeouts		(KERNEL32.@)
 *
 * Sets the timeouts used when reading and writing data to/from COMM ports.
 *
 * PARAMS
 *      hComm           [in]    handle of COMM device
 *      lptimeouts      [in]    pointer to COMMTIMEOUTS structure
 *
 * ReadIntervalTimeout
 *     - converted and passes to linux kernel as c_cc[VTIME]
 * ReadTotalTimeoutMultiplier, ReadTotalTimeoutConstant
 *     - used in ReadFile to calculate GetOverlappedResult's timeout
 * WriteTotalTimeoutMultiplier, WriteTotalTimeoutConstant
 *     - used in WriteFile to calculate GetOverlappedResult's timeout
 *
 * RETURNS
 *
 *  True if the timeouts were set, false otherwise.
 */
WINAPI BOOL SetCommTimeouts(HANDLE hComm, LPCOMMTIMEOUTS lpTimeouts)
{
    SERIAL_TIMEOUTS St;
    DWORD dwBytesReturned;

    TRACE("(%p, %p)\n", hComm, lpTimeouts);

    if (lpTimeouts == NULL) {
	SetLastError(ERROR_INVALID_PARAMETER);
	return FALSE;
    }
    St.ReadIntervalTimeout = lpTimeouts->ReadIntervalTimeout;
    St.ReadTotalTimeoutMultiplier = lpTimeouts->ReadTotalTimeoutMultiplier;
    St.ReadTotalTimeoutConstant = lpTimeouts->ReadTotalTimeoutConstant;
    St.WriteTotalTimeoutMultiplier = lpTimeouts->WriteTotalTimeoutMultiplier;
    St.WriteTotalTimeoutConstant = lpTimeouts->WriteTotalTimeoutConstant;

    return DeviceIoControl(hComm, IOCTL_SERIAL_SET_TIMEOUTS, &St, sizeof(St), NULL, 0,
			   &dwBytesReturned, NULL);
}

/***********************************************************************
 *           GetCommModemStatus   (KERNEL32.@)
 *
 *  Obtains the four control register bits if supported by the hardware.
 *
 * PARAMS
 *
 *      hFile           [in]    The communications device
 *      lpModemStat     [out]   The control register bits
 *
 * RETURNS
 *
 *  True if the communications handle was good and for hardware that
 *  control register access, false otherwise.
 */
WINAPI BOOL GetCommModemStatus(HANDLE hFile, LPDWORD lpModemStat)
{
    DWORD dwBytesReturned;
    return DeviceIoControl(hFile, IOCTL_SERIAL_GET_MODEMSTATUS, NULL, 0, lpModemStat,
			   sizeof(DWORD), &dwBytesReturned, NULL);
}

/***********************************************************************
 *           WaitCommEvent   (KERNEL32.@)
 *
 * Wait until something interesting happens on a COMM port.
 * Interesting things (events) are set by calling SetCommMask before
 * this function is called.
 *
 * RETURNS
 *   TRUE if successful
 *   FALSE if failure
 *
 *   The set of detected events will be written to *lpdwEventMask
 *   ERROR_IO_PENDING will be returned the overlapped structure was passed
 *
 * BUGS:
 *  Only supports EV_RXCHAR and EV_TXEMPTY
 */
WINAPI BOOL WaitCommEvent(HANDLE hFile, /* [in] handle of comm port to wait for */
			  LPDWORD lpdwEvents, /* [out] event(s) that were detected */
			  LPOVERLAPPED lpOverlapped) /* [in/out] for Asynchronous waiting
						      */
{
    return DeviceIoControl(hFile, IOCTL_SERIAL_WAIT_ON_MASK, NULL, 0, lpdwEvents,
			   sizeof(DWORD), NULL, lpOverlapped);
}

/***********************************************************************
 *           GetCommProperties   (KERNEL32.@)
 *
 * This function fills in a structure with the capabilities of the
 * communications port driver.
 *
 * RETURNS
 *
 *  TRUE on success, FALSE on failure
 *  If successful, the lpCommProp structure be filled in with
 *  properties of the comm port.
 */
WINAPI BOOL GetCommProperties(HANDLE hFile, /* [in] handle of the comm port */
			      LPCOMMPROP lpCommProp) /* [out] pointer to struct to be
							filled */
{
    TRACE("(%p %p)\n", hFile, lpCommProp);
    if (!lpCommProp)
	return FALSE;

    /*
     * These values should be valid for LINUX's serial driver
     * FIXME: Perhaps they deserve an #ifdef LINUX
     */
    memset(lpCommProp, 0, sizeof(COMMPROP));
    lpCommProp->wPacketLength = 1;
    lpCommProp->wPacketVersion = 1;
    lpCommProp->dwServiceMask = SP_SERIALCOMM;
    lpCommProp->dwMaxTxQueue = 4096;
    lpCommProp->dwMaxRxQueue = 4096;
    lpCommProp->dwMaxBaud = BAUD_115200;
    lpCommProp->dwProvSubType = PST_RS232;
    lpCommProp->dwProvCapabilities = PCF_DTRDSR | PCF_PARITY_CHECK | PCF_RTSCTS |
				     PCF_TOTALTIMEOUTS;
    lpCommProp->dwSettableParams = SP_BAUD | SP_DATABITS | SP_HANDSHAKING | SP_PARITY |
				   SP_PARITY_CHECK | SP_STOPBITS;
    lpCommProp->dwSettableBaud = BAUD_075 | BAUD_110 | BAUD_134_5 | BAUD_150 | BAUD_300 |
				 BAUD_600 | BAUD_1200 | BAUD_1800 | BAUD_2400 |
				 BAUD_4800 | BAUD_9600 | BAUD_19200 | BAUD_38400 |
				 BAUD_57600 | BAUD_115200;
    lpCommProp->wSettableData = DATABITS_5 | DATABITS_6 | DATABITS_7 | DATABITS_8;
    lpCommProp->wSettableStopParity = STOPBITS_10 | STOPBITS_15 | STOPBITS_20 |
				      PARITY_NONE | PARITY_ODD | PARITY_EVEN |
				      PARITY_MARK | PARITY_SPACE;
    lpCommProp->dwCurrentTxQueue = lpCommProp->dwMaxTxQueue;
    lpCommProp->dwCurrentRxQueue = lpCommProp->dwMaxRxQueue;

    return TRUE;
}

/***********************************************************************
 * FIXME:
 * The functionality of CommConfigDialogA, GetDefaultCommConfig and
 * SetDefaultCommConfig is implemented in a DLL (usually SERIALUI.DLL).
 * This is dependent on the type of COMM port, but since it is doubtful
 * anybody will get around to implementing support for fancy serial
 * ports in WINE, this is hardcoded for the time being.  The name of
 * this DLL should be stored in and read from the system registry in
 * the hive HKEY_LOCAL_MACHINE, key
 * System\\CurrentControlSet\\Services\\Class\\Ports\\????
 * where ???? is the port number... that is determined by PNP
 * The DLL should be loaded when the COMM port is opened, and closed
 * when the COMM port is closed. - MJM 20 June 2000
 ***********************************************************************/
static const WCHAR lpszSerialUI[] = { 's', 'e', 'r', 'i', 'a', 'l', 'u',
				      'i', '.', 'd', 'l', 'l', 0 };

/***********************************************************************
 *           CommConfigDialogA   (KERNEL32.@)
 *
 * Raises a dialog that allows the user to configure a comm port.
 * Fills the COMMCONFIG struct with information specified by the user.
 * This function should call a similar routine in the COMM driver...
 *
 * RETURNS
 *
 *  TRUE on success, FALSE on failure
 *  If successful, the lpCommConfig structure will contain a new
 *  configuration for the comm port, as specified by the user.
 *
 * BUGS
 *  The library with the CommConfigDialog code is never unloaded.
 * Perhaps this should be done when the comm port is closed?
 */
WINAPI BOOL CommConfigDialogA(LPCSTR lpszDevice, /* [in] name of communications device */
			      HWND hWnd, /* [in] parent window for the dialog */
			      LPCOMMCONFIG lpCommConfig) /* [out] pointer to struct to
							    fill */
{
    LPWSTR lpDeviceW = NULL;
    DWORD Len;
    BOOL r;

    TRACE("(%s, %p, %p)\n", debugstr_a(lpszDevice), hWnd, lpCommConfig);

    if (lpszDevice) {
	Len = MultiByteToWideChar(CP_ACP, 0, lpszDevice, -1, NULL, 0);
	lpDeviceW = HeapAlloc(GetProcessHeap(), 0, Len * sizeof(WCHAR));
	MultiByteToWideChar(CP_ACP, 0, lpszDevice, -1, lpDeviceW, Len);
    }
    r = CommConfigDialogW(lpDeviceW, hWnd, lpCommConfig);
    HeapFree(GetProcessHeap(), 0, lpDeviceW);
    return r;
}

/***********************************************************************
 *           CommConfigDialogW   (KERNEL32.@)
 *
 * See CommConfigDialogA.
 */
WINAPI BOOL CommConfigDialogW(LPCWSTR lpszDevice, /* [in] name of communications device */
			      HWND hWnd, /* [in] parent window for the dialog */
			      LPCOMMCONFIG lpCommConfig) /* [out] pointer to struct to
							    fill */
{
    DWORD(WINAPI * pCommConfigDialog)(LPCWSTR, HWND, LPCOMMCONFIG);
    HMODULE hConfigModule;
    DWORD Res = ERROR_INVALID_PARAMETER;

    TRACE("(%ws, %p, %p)\n", lpszDevice, hWnd, lpCommConfig);
    hConfigModule = LoadLibraryW(lpszSerialUI);

    if (hConfigModule) {
	pCommConfigDialog = (void *)GetProcAddress(hConfigModule, "drvCommConfigDialogW");
	if (pCommConfigDialog) {
	    Res = pCommConfigDialog(lpszDevice, hWnd, lpCommConfig);
	}
	FreeLibrary(hConfigModule);
    }

    if (Res)
	SetLastError(Res);
    return (Res == ERROR_SUCCESS);
}

/***********************************************************************
 *           GetCommConfig     (KERNEL32.@)
 *
 * Fill in the COMMCONFIG structure for the comm port hFile
 *
 * RETURNS
 *
 *  TRUE on success, FALSE on failure
 *  If successful, lpCommConfig contains the comm port configuration.
 *
 * BUGS
 *
 */
WINAPI BOOL GetCommConfig(HANDLE hFile, /* [in] The communications device. */
			  LPCOMMCONFIG lpCommConfig, /* [out] The communications
							configuration of the device (if it
							fits). */
			  LPDWORD lpdwSize) /* [in/out] Initially the size of the
					       configuration buffer/structure, afterwards
					       the number of bytes copied to the buffer or
					       the needed size of the buffer. */
{
    BOOL r;

    TRACE("(%p, %p, %p) *lpdwSize: %u\n", hFile, lpCommConfig, lpdwSize,
	  lpdwSize ? *lpdwSize : 0);

    if (lpCommConfig == NULL)
	return FALSE;
    r = *lpdwSize < sizeof(COMMCONFIG); /* TRUE if not enough space */
    *lpdwSize = sizeof(COMMCONFIG);
    if (r)
	return FALSE;

    lpCommConfig->dwSize = sizeof(COMMCONFIG);
    lpCommConfig->wVersion = 1;
    lpCommConfig->wReserved = 0;
    r = GetCommState(hFile, &lpCommConfig->dcb);
    lpCommConfig->dwProviderSubType = PST_RS232;
    lpCommConfig->dwProviderOffset = 0;
    lpCommConfig->dwProviderSize = 0;

    return r;
}

/***********************************************************************
 *           SetCommConfig     (KERNEL32.@)
 *
 *  Sets the configuration of the communications device.
 *
 * RETURNS
 *
 *  True on success, false if the handle was bad is not a communications device.
 */
WINAPI BOOL SetCommConfig(HANDLE hFile, /* [in] The communications device. */
			  LPCOMMCONFIG lpCommConfig, /* [in] The desired configuration. */
			  DWORD dwSize) /* [in] size of the lpCommConfig struct */
{
    TRACE("(%p, %p, %u)\n", hFile, lpCommConfig, dwSize);
    return SetCommState(hFile, &lpCommConfig->dcb);
}

/***********************************************************************
 *           SetDefaultCommConfigW  (KERNEL32.@)
 *
 * Initializes the default configuration for a communication device.
 *
 * PARAMS
 *  lpszDevice   [I] Name of the device targeted for configuration
 *  lpCommConfig [I] PTR to a buffer with the configuration for the device
 *  dwSize       [I] Number of bytes in the buffer
 *
 * RETURNS
 *  Failure: FALSE
 *  Success: TRUE, and default configuration saved
 *
 */
WINAPI BOOL SetDefaultCommConfigW(LPCWSTR lpszDevice, LPCOMMCONFIG lpCommConfig,
				  DWORD dwSize)
{
    BOOL(WINAPI * lpfnSetDefaultCommConfig)(LPCWSTR, LPCOMMCONFIG, DWORD);
    HMODULE hConfigModule;
    BOOL r = FALSE;

    TRACE("(%ws, %p, %u)\n", lpszDevice, lpCommConfig, dwSize);

    hConfigModule = LoadLibraryW(lpszSerialUI);
    if (!hConfigModule)
	return r;

    lpfnSetDefaultCommConfig = (void *)GetProcAddress(hConfigModule, "drvSetDefaultCommCo"
								     "nfigW");
    if (lpfnSetDefaultCommConfig)
	r = lpfnSetDefaultCommConfig(lpszDevice, lpCommConfig, dwSize);

    FreeLibrary(hConfigModule);

    return r;
}

/***********************************************************************
 *           SetDefaultCommConfigA     (KERNEL32.@)
 *
 * Initializes the default configuration for a communication device.
 *
 * See SetDefaultCommConfigW.
 *
 */
WINAPI BOOL SetDefaultCommConfigA(LPCSTR lpszDevice, LPCOMMCONFIG lpCommConfig,
				  DWORD dwSize)
{
    BOOL r;
    LPWSTR lpDeviceW = NULL;
    DWORD Len;

    TRACE("(%s, %p, %u)\n", debugstr_a(lpszDevice), lpCommConfig, dwSize);

    if (lpszDevice) {
	Len = MultiByteToWideChar(CP_ACP, 0, lpszDevice, -1, NULL, 0);
	lpDeviceW = HeapAlloc(GetProcessHeap(), 0, Len * sizeof(WCHAR));
	MultiByteToWideChar(CP_ACP, 0, lpszDevice, -1, lpDeviceW, Len);
    }
    r = SetDefaultCommConfigW(lpDeviceW, lpCommConfig, dwSize);
    HeapFree(GetProcessHeap(), 0, lpDeviceW);
    return r;
}

/***********************************************************************
 *           GetDefaultCommConfigW   (KERNEL32.@)
 *
 *   Acquires the default configuration of the specified communication device. (unicode)
 *
 *  RETURNS
 *
 *   True on successful reading of the default configuration,
 *   if the device is not found or the buffer is too small.
 */
WINAPI BOOL GetDefaultCommConfigW(LPCWSTR lpszName, /* [in] The unicode name of the device
						       targeted for configuration. */
				  LPCOMMCONFIG lpCC, /* [out] The default configuration
							for the device. */
				  LPDWORD lpdwSize) /* [in/out] Initially the size of the
						       default configuration buffer,
						       afterwards the number of bytes
						       copied to the buffer or the needed
						       size of the buffer. */
{
    DWORD(WINAPI * pGetDefaultCommConfig)(LPCWSTR, LPCOMMCONFIG, LPDWORD);
    HMODULE hConfigModule;
    DWORD Res = ERROR_INVALID_PARAMETER;

    TRACE("(%ws, %p, %p)  *lpdwSize: %u\n", lpszName, lpCC, lpdwSize,
	  lpdwSize ? *lpdwSize : 0);
    hConfigModule = LoadLibraryW(lpszSerialUI);

    if (hConfigModule) {
	pGetDefaultCommConfig = (void *)GetProcAddress(hConfigModule, "drvGetDefaultCommC"
								      "onfigW");
	if (pGetDefaultCommConfig) {
	    Res = pGetDefaultCommConfig(lpszName, lpCC, lpdwSize);
	}
	FreeLibrary(hConfigModule);
    }

    if (Res)
	SetLastError(Res);
    return (Res == ERROR_SUCCESS);
}

/**************************************************************************
 *         GetDefaultCommConfigA		(KERNEL32.@)
 *
 *   Acquires the default configuration of the specified communication device. (ascii)
 *
 *  RETURNS
 *
 *   True on successful reading of the default configuration,
 *   if the device is not found or the buffer is too small.
 */
WINAPI BOOL GetDefaultCommConfigA(LPCSTR lpszName, /* [in] The ascii name of the device
						      targeted for configuration. */
				  LPCOMMCONFIG lpCC, /* [out] The default configuration
							for the device. */
				  LPDWORD lpdwSize) /* [in/out] Initially the size of the
						       default configuration buffer,
						       afterwards the number of bytes
						       copied to the buffer or the needed
						       size of the buffer. */
{
    BOOL Ret = FALSE;
    UNICODE_STRING lpszNameW;

    TRACE("(%s, %p, %p)  *lpdwSize: %u\n", debugstr_a(lpszName), lpCC, lpdwSize,
	  lpdwSize ? *lpdwSize : 0);
    if (lpszName)
	RtlCreateUnicodeStringFromAsciiz(&lpszNameW, lpszName);
    else
	lpszNameW.Buffer = NULL;

    Ret = GetDefaultCommConfigW(lpszNameW.Buffer, lpCC, lpdwSize);

    RtlFreeUnicodeString(&lpszNameW);
    return Ret;
}
