#pragma once

#include <string.h>
#include <stdint.h>
#include <nt.h>
#include <sel4/sel4.h>
#include <ke.h>
#include <services.h>
#include <debug.h>
#include <assert.h>

/* We cannot include win32 headers so define ULongToPtr here */
static inline void *ULongToPtr(const unsigned long ul)
{
    return (void*)((ULONG_PTR)ul);
}
#define UlongToPtr ULongToPtr
