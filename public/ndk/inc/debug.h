/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS kernel
 * FILE:            include/reactos/debug.h
 * PURPOSE:         Useful debugging macros
 * PROGRAMMERS:     David Welch (welch@mcmail.com)
 *                  Hermes Belusca-Maito (hermes.belusca@sfr.fr)
 */

/*
 * NOTE: Define NDEBUG before including this header
 * to disable debugging macros.
 */

#pragma once

#ifndef _NTURTL_H_

__cdecl ULONG DbgPrint(PCSTR Format, ...) __attribute__ ((format(printf, 1, 2)));

NTSYSAPI __cdecl ULONG DbgPrintEx(IN ULONG ComponentId,
				  IN ULONG Level,
				  IN PCSTR Format,
				  ...) __attribute__ ((format(printf, 3, 4)));

NTSYSAPI NTAPI VOID RtlAssert(IN PVOID FailedAssertion,
			      IN PVOID FileName,
			      IN ULONG LineNumber,
			      IN OPTIONAL PCHAR Message);

#endif /* !defined(_NTURTL_H_) */

#ifndef __RELFILE__
#define __RELFILE__ __FILE__
#endif

#ifndef assert
#if DBG && !defined(NASSERT)
#define assert(x) if (!(x)) { RtlAssert((PVOID)#x, (PVOID)__RELFILE__, __LINE__, (PCHAR)""); }
#else
#define assert(x) ((VOID) 0)
#endif
#endif

#ifndef ASSERT
#if DBG && !defined(NASSERT)
#define ASSERT(x) if (!(x)) { RtlAssert((PVOID)#x, (PVOID)__RELFILE__, __LINE__, (PCHAR)""); }
#else
#define ASSERT(x) ((VOID) 0)
#endif
#endif

#ifndef ASSERTMSG
#if DBG && !defined(NASSERT)
#define ASSERTMSG(m, x) if (!(x)) { RtlAssert((PVOID)#x, __RELFILE__, __LINE__, m); }
#else
#define ASSERTMSG(m, x) ((VOID) 0)
#endif
#endif

/* For internal purposes only */
#define __NOTICE(level, fmt, ...)   DbgPrint(#level ":  %s at %s:%d " fmt, __FUNCTION__, __RELFILE__, __LINE__, ##__VA_ARGS__)

/* Print stuff only on Debug Builds*/
#if DBG

/* These are always printed */
#define DPRINT1(fmt, ...) do {						\
        if (DbgPrint("(%s:%d) " fmt, __RELFILE__, __LINE__, ##__VA_ARGS__)) \
            DbgPrint("(%s:%d) DbgPrint() failed!\n", __RELFILE__, __LINE__); \
    } while (0)

/* These are printed only if NDEBUG is NOT defined */
#ifndef NDEBUG

#define DPRINT(fmt, ...) do {						\
	if (DbgPrint("(%s:%d) " fmt, __RELFILE__, __LINE__, ##__VA_ARGS__)) \
	    DbgPrint("(%s:%d) DbgPrint() failed!\n", __RELFILE__, __LINE__); \
    } while (0)

#else

#if defined(_MSC_VER)
#define DPRINT   __noop
#else
#define DPRINT(...) do { if(0) { DbgPrint(__VA_ARGS__); } } while(0)
#endif

#endif

#define UNIMPLEMENTED         __NOTICE(WARNING, "is UNIMPLEMENTED!\n")
#define UNIMPLEMENTED_ONCE    do { static int bWarnedOnce = 0; if (!bWarnedOnce) { bWarnedOnce++; UNIMPLEMENTED; } } while (0)

#define ERR_(ch, fmt, ...)    DbgPrintEx(DPFLTR_##ch##_ID, DPFLTR_ERROR_LEVEL, "(%s:%d) " fmt, __RELFILE__, __LINE__, ##__VA_ARGS__)
#define WARN_(ch, fmt, ...)   DbgPrintEx(DPFLTR_##ch##_ID, DPFLTR_WARNING_LEVEL, "(%s:%d) " fmt, __RELFILE__, __LINE__, ##__VA_ARGS__)
#define TRACE_(ch, fmt, ...)  DbgPrintEx(DPFLTR_##ch##_ID, DPFLTR_TRACE_LEVEL, "(%s:%d) " fmt, __RELFILE__, __LINE__, ##__VA_ARGS__)
#define INFO_(ch, fmt, ...)   DbgPrintEx(DPFLTR_##ch##_ID, DPFLTR_INFO_LEVEL, "(%s:%d) " fmt, __RELFILE__, __LINE__, ##__VA_ARGS__)

#define ERR__(ch, fmt, ...)    DbgPrintEx(ch, DPFLTR_ERROR_LEVEL, "(%s:%d) " fmt, __RELFILE__, __LINE__, ##__VA_ARGS__)
#define WARN__(ch, fmt, ...)   DbgPrintEx(ch, DPFLTR_WARNING_LEVEL, "(%s:%d) " fmt, __RELFILE__, __LINE__, ##__VA_ARGS__)
#define TRACE__(ch, fmt, ...)  DbgPrintEx(ch, DPFLTR_TRACE_LEVEL, "(%s:%d) " fmt, __RELFILE__, __LINE__, ##__VA_ARGS__)
#define INFO__(ch, fmt, ...)   DbgPrintEx(ch, DPFLTR_INFO_LEVEL, "(%s:%d) " fmt, __RELFILE__, __LINE__, ##__VA_ARGS__)

#else /* not DBG */

/* On non-debug builds, we never show these */
#define UNIMPLEMENTED
#define UNIMPLEMENTED_ONCE
#if defined(_MSC_VER)
#define DPRINT1   __noop
#define DPRINT    __noop

#define ERR_(ch, ...)      __noop
#define WARN_(ch, ...)     __noop
#define TRACE_(ch, ...)    __noop
#define INFO_(ch, ...)     __noop

#define ERR__(ch, ...)     __noop
#define WARN__(ch, ...)    __noop
#define TRACE__(ch, ...)   __noop
#define INFO__(ch, ...)    __noop
#else
#define DPRINT1(...) do { if(0) { DbgPrint(__VA_ARGS__); } } while(0)
#define DPRINT(...) do { if(0) { DbgPrint(__VA_ARGS__); } } while(0)

#define ERR_(ch, ...) do { if(0) { DbgPrint(__VA_ARGS__); } } while(0)
#define WARN_(ch, ...) do { if(0) { DbgPrint(__VA_ARGS__); } } while(0)
#define TRACE_(ch, ...) do { if(0) { DbgPrint(__VA_ARGS__); } } while(0)
#define INFO_(ch, ...) do { if(0) { DbgPrint(__VA_ARGS__); } } while(0)

#define ERR__(ch, ...) do { if(0) { DbgPrint(__VA_ARGS__); } } while(0)
#define WARN__(ch, ...) do { if(0) { DbgPrint(__VA_ARGS__); } } while(0)
#define TRACE__(ch, ...) do { if(0) { DbgPrint(__VA_ARGS__); } } while(0)
#define INFO__(ch, ...) do { if(0) { DbgPrint(__VA_ARGS__); } } while(0)
#endif /* _MSC_VER */

#endif /* not DBG */

/******************************************************************************/
/*
 * Declare a target-dependent process termination procedure.
 */
#ifndef _NTOSKRNL_             /* User-Mode */
#define TerminateCurrentProcess(Status) NtTerminateProcess(NtCurrentProcess(), (Status))
#endif

/* For internal purposes only */
#define __ERROR_DBGBREAK(...)			\
    do {					\
	DbgPrint("" __VA_ARGS__);		\
	DbgBreakPoint();			\
    } while (0)

/* For internal purposes only */
#define __ERROR_FATAL(Status, ...)		\
    do {					\
	DbgPrint("" __VA_ARGS__);		\
	DbgBreakPoint();			\
	TerminateCurrentProcess(Status);	\
    } while (0)

/*
 * These macros are designed to display an optional printf-like
 * user-defined message and to break into the debugger.
 * After that they allow to continue the program execution.
 */
#define ERROR_DBGBREAK(...)			\
    do {					\
	__NOTICE(ERROR, "\n");			\
	__ERROR_DBGBREAK(__VA_ARGS__);		\
    } while (0)

#define UNIMPLEMENTED_DBGBREAK(...)		\
    do {                                        \
	__NOTICE(ERROR, "is UNIMPLEMENTED!\n"); \
	__ERROR_DBGBREAK(__VA_ARGS__);          \
    } while (0)

/*
 * These macros are designed to display an optional printf-like
 * user-defined message and to break into the debugger.
 * After that they halt the execution of the current thread.
 */
#define ERROR_FATAL(...)					\
    do {                                                        \
	__NOTICE(UNRECOVERABLE ERROR, "\n");                    \
	__ERROR_FATAL(STATUS_ASSERTION_FAILURE, __VA_ARGS__);   \
    } while (0)

#define UNIMPLEMENTED_FATAL(...)				\
    do {                                                        \
	__NOTICE(UNRECOVERABLE ERROR, "is UNIMPLEMENTED!\n");   \
	__ERROR_FATAL(STATUS_NOT_IMPLEMENTED, __VA_ARGS__);     \
    } while (0)
/******************************************************************************/

#define ASSERT_IRQL_LESS_OR_EQUAL(x) ASSERT(KeGetCurrentIrql()<=(x))
#define ASSERT_IRQL_EQUAL(x) ASSERT(KeGetCurrentIrql()==(x))
#define ASSERT_IRQL_LESS(x) ASSERT(KeGetCurrentIrql()<(x))

#define __STRING2__(x) #x
#define __STRING__(x) __STRING2__(x)
#define __STRLINE__ __STRING__(__LINE__)

#if !defined(_MSC_VER) && !defined(__pragma)
#define __pragma(x) _Pragma(#x)
#endif

#define _WARN(msg) __pragma(message("WARNING! Line " __STRLINE__ ": " msg))
