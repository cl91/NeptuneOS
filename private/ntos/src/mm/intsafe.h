/*
 * This header file is shamelessly stolen from the ReactOS source code.
 */

#pragma once

/* TODO: Intsafe should be made into a library, as it's generally useful */
static inline BOOLEAN Intsafe_CanAddULongPtr(IN ULONG_PTR Addend1, IN ULONG_PTR Addend2)
{
    return Addend1 <= (MAXULONG_PTR - Addend2);
}

static inline BOOLEAN Intsafe_CanAddLong64(IN LONG64 Addend1, IN LONG64 Addend2)
{
    return Addend1 <= (MAXLONGLONG - Addend2);
}

static inline BOOLEAN Intsafe_CanAddULong32(IN ULONG Addend1, IN ULONG Addend2)
{
    return Addend1 <= (MAXULONG - Addend2);
}

static inline BOOLEAN Intsafe_AddULong32(OUT PULONG Result,
					 IN ULONG Addend1,
					 IN ULONG Addend2)
{
    if (!Intsafe_CanAddULong32(Addend1, Addend2))
	return FALSE;

    *Result = Addend1 + Addend2;
    return TRUE;
}

static inline BOOLEAN Intsafe_CanMulULong32(IN ULONG Factor1, IN ULONG Factor2)
{
    return Factor1 <= (MAXULONG / Factor2);
}

static inline BOOLEAN Intsafe_CanOffsetPointer(IN CONST VOID * Pointer, IN SIZE_T Offset)
{
    /* FIXME: (PVOID)MAXULONG_PTR isn't necessarily a valid address */
    return Intsafe_CanAddULongPtr((ULONG_PTR)Pointer, Offset);
}

static inline BOOLEAN IsPowerOf2(IN ULONG Number)
{
    if(Number == 0)
	return FALSE;
    return (Number & (Number - 1)) == 0;
}

static inline ULONG ModPow2(IN ULONG Address, IN ULONG Alignment)
{
    assert(IsPowerOf2(Alignment));
    return Address & (Alignment - 1);
}

static inline BOOLEAN AlignUp(OUT PULONG AlignedAddress,
			      IN ULONG Address,
			      IN ULONG Alignment)
{
    ULONG nExcess = ModPow2(Address, Alignment);

    if(nExcess == 0)
    {
	*AlignedAddress = Address;
	return nExcess == 0;
    }
    else
	return Intsafe_AddULong32(AlignedAddress, Address, Alignment - nExcess);
}
