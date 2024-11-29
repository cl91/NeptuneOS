#include <ntos.h>

#if defined(_M_IX86) || defined(_M_AMD64)
/*
 * This file provides the implementations for MSVC intrinsic functions.
 * These are compiler builtins for PE targets but since we are ELF targets
 * we need to provide these ourselves.
 */

void __cpuid(int CPUInfo[4],
	     int InfoType)
{
    __asm__ __volatile__("cpuid"
			 : "=a" (CPUInfo[0]), "=b" (CPUInfo[1]),
			   "=c" (CPUInfo[2]), "=d" (CPUInfo[3])
			 : "a" (InfoType));
}

void __cpuidex(int CPUInfo[4],
	       int InfoType,
	       int ECXValue)
{
    __asm__ __volatile__("cpuid" :
			 "=a" (CPUInfo[0]), "=b" (CPUInfo[1]),
			 "=c" (CPUInfo[2]), "=d" (CPUInfo[3])
			 : "a" (InfoType), "c" (ECXValue));
}
#endif
