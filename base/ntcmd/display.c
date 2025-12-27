/*++

Copyright (c) Alex Ionescu.  All rights reserved.
Copyright (c) 2011 amdf.

Module Name:

    display.c

Abstract:

    The Native Command Line Interface is the command shell for Neptune OS.
    This module handles displaying output to screen.

Environment:

    Native mode

Revision History:

    Alex Ionescu - Started Implementation - 01-Mar-06
    Alex Ionescu - Reworked architecture - 23-Mar-06
    amdf - Display buffer extended (was too small) - 22-Feb-11

--*/
#include "ntcmd.h"
#include "ntexapi.h"

/*++
 * @name RtlCliPutChar
 *
 * The RtlCliPutChar routine displays a character.
 *
 * @param Char
 *        Character to print out.
 *
 * @return STATUS_SUCCESS or failure code.
 *
 * @remarks None.
 *
 *--*/
NTSTATUS RtlCliPutChar(IN WCHAR Char)
{
    WCHAR PutChar[] = { Char, L'\0' };
    UNICODE_STRING CharString;
    RtlInitUnicodeString(&CharString, PutChar);

    //
    // Print the character
    //
    return NtDisplayString(&CharString);
}

/*++
 * @name RtlCliDisplayString
 *
 * The RtlCliDisplayString routine FILLMEIN
 *
 * @param Message
 *        FILLMEIN
 *
 * @param ... (Ellipsis)
 *        There is no set number of parameters.
 *
 * @return NTSTATUS
 *
 * @remarks Documentation for this routine needs to be completed.
 *
 *--*/
#define CLI_DISPLAY_STRING_BUFSIZE	1024
NTSTATUS RtlCliDisplayString(IN PCH Message, ...)
{
    va_list MessageList;
    NTSTATUS Status;

    //
    // Allocate Memory for the String Buffer
    //
    PCHAR MessageBuffer = RtlAllocateHeap(RtlGetProcessHeap(), 0, CLI_DISPLAY_STRING_BUFSIZE);
    if (!MessageBuffer) {
	return STATUS_NO_MEMORY;
    }

    //
    // First, combine the message
    //
    va_start(MessageList, Message);
    _vsnprintf(MessageBuffer, CLI_DISPLAY_STRING_BUFSIZE, Message, MessageList);
    va_end(MessageList);

    //
    // Display it on screen
    //
    Status = NtDisplayStringA(MessageBuffer);

    //
    // Free Memory
    //
    RtlFreeHeap(RtlGetProcessHeap(), 0, MessageBuffer);

    //
    // Return to the caller
    //
    return Status;
}
