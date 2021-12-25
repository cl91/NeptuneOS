#pragma once

#include <nt.h>

/*
 * X86 Port routines
 */
__cdecl NTSYSAPI UCHAR __inbyte(IN USHORT PortNum);
__cdecl NTSYSAPI VOID __outbyte(IN USHORT PortNum,
				IN UCHAR Data);
#define READ_PORT_UCHAR(PortNum)	__inbyte(PortNum)
#define WRITE_PORT_UCHAR(PortNum, Data)	__outbyte(PortNum, Data)

NTAPI NTSYSAPI BOOLEAN HalMakeBeep(IN ULONG Frequency);
