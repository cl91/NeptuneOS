/**
 * This file has no copyright assigned and is placed in the Public Domain.
 * This file is part of the w64 mingw-runtime package.
 * No warranty is given; refer to the file DISCLAIMER within this package.
 */
#ifndef _INC_EXCPT
#define _INC_EXCPT

#include <crtdefs.h>

#pragma pack(push,_CRT_PACKING)

#ifdef __cplusplus
extern "C" {
#endif

typedef enum _EXCEPTION_DISPOSITION {
    ExceptionContinueExecution,
    ExceptionContinueSearch,
    ExceptionNestedException,
    ExceptionCollidedUnwind,
} EXCEPTION_DISPOSITION;

#ifdef __i386__
  struct _EXCEPTION_RECORD;
  struct _CONTEXT;

  EXCEPTION_DISPOSITION
  __cdecl
  _except_handler(
    _In_ struct _EXCEPTION_RECORD *_ExceptionRecord,
    _In_ void *_EstablisherFrame,
    _Inout_ struct _CONTEXT *_ContextRecord,
    _Inout_ void *_DispatcherContext);

#elif defined(__x86_64) || defined(__aarch64__)

  struct _EXCEPTION_RECORD;
  struct _CONTEXT;
  struct _DISPATCHER_CONTEXT;

  _CRTIMP
  EXCEPTION_DISPOSITION
  __cdecl
  __C_specific_handler(
    _In_ struct _EXCEPTION_RECORD *_ExceptionRecord,
    _In_ void *_EstablisherFrame,
    _Inout_ struct _CONTEXT *_ContextRecord,
    _Inout_ struct _DISPATCHER_CONTEXT *_DispatcherContext);

#else
  #error "Unsupported architecture."
#endif

#if defined(_MSC_VER) || (defined(__clang__) && defined(__SEH__))
#define GetExceptionCode _exception_code
#define exception_code _exception_code
#define GetExceptionInformation (struct _EXCEPTION_POINTERS *)_exception_info
#define exception_info (struct _EXCEPTION_POINTERS *)_exception_info
#define AbnormalTermination _abnormal_termination
#define abnormal_termination _abnormal_termination
  unsigned long __cdecl _exception_code(void);
  void *__cdecl _exception_info(void);
  int __cdecl _abnormal_termination(void);
#endif

#define EXCEPTION_EXECUTE_HANDLER 1
#define EXCEPTION_CONTINUE_SEARCH 0
#define EXCEPTION_CONTINUE_EXECUTION -1

#ifdef __cplusplus
}
#endif

#pragma pack(pop)
#endif
