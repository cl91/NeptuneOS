#pragma once

#include <nt.h>

VOID DbgPrint(PCSTR Format, ...) __attribute__ ((format(printf, 1, 2)));

#define DbgTrace(...) { DbgPrint("%s:  ", __func__); DbgPrint(__VA_ARGS__); }

#define DPRINT1 DbgTrace
