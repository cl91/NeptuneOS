#include <nt.h>
#include <debug.h>
#include <sel4/sel4.h>

static PCSTR KiDbgErrorCodeToStr(IN int Error)
{
    switch (Error) {
    case seL4_InvalidArgument:
	return "Invalid argument";
    case seL4_InvalidCapability:
	return "Invalid capability";
    case seL4_IllegalOperation:
	return "Illegal operation";
    case seL4_RangeError:
	return "Range error";
    case seL4_AlignmentError:
	return "Alignment error";
    case seL4_FailedLookup:
	return "Failed lookup";
    case seL4_TruncatedMessage:
	return "Truncated Message";
    case seL4_DeleteFirst:
	return "Delete first";
    case seL4_RevokeFirst:
	return "Revoke first";
    case seL4_NotEnoughMemory:
	return "Not enough memory";
    }

    return "Unknown error";
}

static VOID KiDbgDumpFailedLookupError()
{
    DbgPrint("    Lookup failed for a %s capability.\n", seL4_GetMR(0) ? "source" : "destination");
    DbgPrint("    Failure type is ");
    switch (seL4_GetMR(1)) {
    case seL4_NoFailure:
	DbgPrint("no failure???\n");
    case seL4_InvalidRoot:
	DbgPrint("invalid root\n");
	break;
    case seL4_MissingCapability:
	DbgPrint("missing capability (%zd bits left)\n", seL4_GetMR(2));
	break;
    case seL4_DepthMismatch:
	DbgPrint("depth mismatch (%zd bits of CPTR remaining to be decoded,"
		 " %zd bits that the current CNode being traversed resolved)\n",
		 seL4_GetMR(2), seL4_GetMR(3));
	break;
    case seL4_GuardMismatch:
	DbgPrint("guard mismatch (%zd bits of CPTR remaining to be decoded,"
		 " CNode guard is 0x%zx, CNode guard size is %zd)\n",
		 seL4_GetMR(2), seL4_GetMR(3), seL4_GetMR(4));
	break;
    }
}

VOID KeDbgDumpIPCError(IN int Error)
{
    DbgPrint("IPC Error code %d (%s):\n", Error, KiDbgErrorCodeToStr(Error));

    switch (Error) {
    case seL4_InvalidArgument:
	DbgPrint("    Invalid argument number is %zd\n", seL4_GetMR(0));
	break;
    case seL4_InvalidCapability:
	DbgPrint("    Invalid capability is 0x%zx\n", seL4_GetMR(0));
	break;
    case seL4_IllegalOperation:
	break;
    case seL4_RangeError:
	DbgPrint("    Allowed range: [0x%zx, 0x%zx]\n", seL4_GetMR(0), seL4_GetMR(1));
	break;
    case seL4_AlignmentError:
	break;
    case seL4_FailedLookup:
	KiDbgDumpFailedLookupError();
	break;
    case seL4_TruncatedMessage:
	break;
    case seL4_DeleteFirst:
	break;
    case seL4_RevokeFirst:
	break;
    case seL4_NotEnoughMemory:
	DbgPrint("    Amount of memory available: 0x%zx bytes\n", seL4_GetMR(0));
	break;
    }
}
