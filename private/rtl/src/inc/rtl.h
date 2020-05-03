#pragma once

#include <nt.h>

VOID DbgPrint(PCSTR Format, ...);

#define DPRINT1 DbgPrint
