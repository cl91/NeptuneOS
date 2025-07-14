#pragma once

#include <ntos.h>

/* event.c */
NTSTATUS EiInitEventObject();
NTSTATUS EiCreateEvent(IN PPROCESS Process,
		       IN EVENT_TYPE EventType,
		       OUT PEVENT_OBJECT *Event);

/* lpc.c */
NTSTATUS EiInitPortObject();
