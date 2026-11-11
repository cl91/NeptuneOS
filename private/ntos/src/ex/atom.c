#include "ei.h"

NTSTATUS NtAddAtom(IN ASYNC_STATE AsyncState,
		   IN PCSTR AtomName,
		   OUT PRTL_ATOM Atom)
{
    UNIMPLEMENTED;
}

NTSTATUS NtDeleteAtom(IN ASYNC_STATE AsyncState,
		      IN RTL_ATOM Atom)
{
    UNIMPLEMENTED;
}

NTSTATUS NtFindAtom(IN ASYNC_STATE AsyncState,
		    IN PCSTR AtomName,
		    OUT OPTIONAL PRTL_ATOM Atom)
{
    UNIMPLEMENTED;
}

NTSTATUS NtQueryInformationAtom(IN ASYNC_STATE AsyncState,
				IN RTL_ATOM Atom,
				IN ATOM_INFORMATION_CLASS AtomInformationClass,
				OUT PVOID AtomInformation,
				IN ULONG AtomInformationLength,
				OUT OPTIONAL PULONG ReturnLength)
{
    UNIMPLEMENTED;
}
