#ifndef _STORSWTR_H_
#define _STORSWTR_H_

#ifdef TRACE_LEVEL_FATAL
#undef TRACE_LEVEL_FATAL
#endif

#ifdef TRACE_LEVEL_ERROR
#undef TRACE_LEVEL_ERROR
#endif

#ifdef TRACE_LEVEL_WARNING
#undef TRACE_LEVEL_WARNING
#endif

#ifdef TRACE_LEVEL_INFORMATION
#undef TRACE_LEVEL_INFORMATION
#endif

#ifdef TRACE_LEVEL_VERBOSE
#undef TRACE_LEVEL_VERBOSE
#endif

#define TRACE_LEVEL_FATAL 1
#define TRACE_LEVEL_ERROR 2
#define TRACE_LEVEL_WARNING 3
#define TRACE_LEVEL_INFORMATION 4
#define TRACE_LEVEL_VERBOSE 5

#ifdef DEBUG_USE_WPP
#undef DEBUG_USE_WPP
#endif

#ifdef WPP_INIT_TRACING
#undef WPP_INIT_TRACING
#endif

#ifdef WPP_CLEANUP
#undef WPP_CLEANUP
#endif

#define WPP_INIT_TRACING(_DRIVER, _REGISTRY)
#define WPP_CLEANUP(_DRIVER)

typedef enum _DEBUG_FLAGS {
    TRACE_FLAG_GENERAL = 0,
    TRACE_FLAG_PNP,
    TRACE_FLAG_POWER,
    TRACE_FLAG_RW,
    TRACE_FLAG_IOCTL,
    TRACE_FLAG_QUEUE,
    TRACE_FLAG_WMI,
    TRACE_FLAG_TIMER,
    TRACE_FLAG_INIT,
    TRACE_FLAG_LOCK,
    TRACE_FLAG_DEBUG1,
    TRACE_FLAG_DEBUG2,
    TRACE_FLAG_MCN,
    TRACE_FLAG_ISR,
    TRACE_FLAG_ENUM,
    TRACE_FLAG_LOGOTEST,
    TRACE_FLAG_DUMP,
    TRACE_FLAG_SCSI
} DEBUG_FLAGS, *PDEBUG_FLAGS;

#if DBG

#define TracePrint(x) StorDebugPrint x

#if DEBUG_MAIN_SOURCE

void StorDebugPrint(int DebugPrintLevel,
		    DEBUG_FLAGS DebugPrintFlags,
		    PCCHAR DebugMessage, ...)
{
    va_list ap;
    UNREFERENCED_PARAMETER(DebugPrintFlags);
    va_start(ap, DebugMessage);
    vDbgPrintEx(DEBUG_COMP_ID, DebugPrintLevel, DebugMessage, ap);
    va_end(ap);
}

#else

void StorDebugPrint(int DebugPrintLevel,
		    DEBUG_FLAGS DebugPrintFlags,
		    PCCHAR DebugMessage, ...);

#endif // DEBUG_MAIN_SOURCE

#else // DBG && (NTDDI_VERSION >= NTDDI_WINXP)

#define TracePrint(x)

#endif // DBG && (NTDDI_VERSION >= NTDDI_WINXP)

#endif // _STORSWTR_H_
