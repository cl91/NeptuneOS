/* This file can be included multiple times */

#ifdef DbgPrint
#undef DbgPrint
#endif

#ifdef DbgTrace
#undef DbgTrace
#endif

#if defined(CONFIG_DEBUG_BUILD) || defined(DEBUG) || defined(DBG) || defined(_DEBUG)

#ifndef DbgTrace
#if defined(_NTOSKRNL_) || defined(_NTDLL_)
extern PCSTR RtlpDbgTraceModuleName;
#else
extern DECLSPEC_IMPORT PCSTR RtlpDbgTraceModuleName;
#endif	/* _NTOSKRNL_ */
#define DbgTrace(...) { DbgPrint("%s %s(%d):  ", RtlpDbgTraceModuleName, __func__, __LINE__); DbgPrint(__VA_ARGS__); }
#endif	/* DbgTrace */

#else

#ifndef DbgTrace
#define DbgTrace(...)
#endif
#define DbgPrint(...)

#endif	/* DEBUG */
