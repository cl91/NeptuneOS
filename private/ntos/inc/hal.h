#pragma once

#include <nt.h>

NTSTATUS HalInitializeCmos(VOID);
BOOLEAN HalQueryRealTimeClock(OUT PTIME_FIELDS Time);
BOOLEAN HalSetRealTimeClock(IN PTIME_FIELDS Time);
