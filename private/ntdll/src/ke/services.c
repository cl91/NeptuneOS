#include <ntdll.h>
#include <client_svc_helpers.h>

extern __thread seL4_CPtr KiSystemServiceCap;

#include <ntdll_syssvc_gen.c>
