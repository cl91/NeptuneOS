#pragma once

#include <services.h>
#include <halsvc_gen.h>

compile_assert(TOO_MANY_HAL_SERVICES, NUMBER_OF_HAL_SERVICES < 0x1000UL);

#define DRIVER_IRP_BUFFER_RESERVE	(64 * 1024)
#define DRIVER_IRP_BUFFER_COMMIT	(8 * 1024)

/*
 * This is the actual data structure being passed between the server
 * task and the client driver processes. The public struct IRP is exposed
 * in wdm.h in order to remain semi-compatible with Windows/ReactOS.
 */
typedef struct _IO_REQUEST_PACKET {
} IO_REQUEST_PACKET, *PIO_REQUEST_PACKET;
