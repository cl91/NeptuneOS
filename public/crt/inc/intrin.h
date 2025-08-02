#pragma once

/*
 * Stack frame addresses
 */
#define _AddressOfReturnAddress() (&(((void **)(__builtin_frame_address(0)))[1]))

/*
 * Atomic operations
 */
static inline char InterlockedCompareExchange8(volatile char *Destination,
					       char Exchange,
					       char Comperand)
{
    return __sync_val_compare_and_swap(Destination, Comperand, Exchange);
}

static inline short InterlockedCompareExchange16(volatile short *Destination,
						 short Exchange,
						 short Comperand)
{
    return __sync_val_compare_and_swap(Destination, Comperand, Exchange);
}

static inline __cdecl int InterlockedCompareExchange(volatile int *Destination,
						     int Exchange,
						     int Comperand)
{
    return __sync_val_compare_and_swap(Destination, Comperand, Exchange);
}

static inline void *InterlockedCompareExchangePointer(void *volatile *Destination,
						      void *Exchange,
						      void *Comperand)
{
    return (void *)__sync_val_compare_and_swap(Destination, Comperand, Exchange);
}

static inline char InterlockedExchange8(volatile char *Target, char Value)
{
    /* NOTE: __sync_lock_test_and_set would be an acquire barrier, so we force a full barrier */
    __sync_synchronize();
    return __sync_lock_test_and_set(Target, Value);
}

static inline short InterlockedExchange16(volatile short *Target, short Value)
{
    /* NOTE: __sync_lock_test_and_set would be an acquire barrier, so we force a full barrier */
    __sync_synchronize();
    return __sync_lock_test_and_set(Target, Value);
}

static inline __cdecl int InterlockedExchange(volatile int *Target, int Value)
{
    /* NOTE: __sync_lock_test_and_set would be an acquire barrier, so we force a full barrier */
    __sync_synchronize();
    return __sync_lock_test_and_set(Target, Value);
}

static inline void *InterlockedExchangePointer(void *volatile *Target, void *Value)
{
    /* NOTE: __sync_lock_test_and_set would be an acquire barrier, so we force a full barrier */
    __sync_synchronize();
    return (void *)__sync_lock_test_and_set(Target, Value);
}

static inline char InterlockedExchangeAdd8(char volatile *Addend, char Value)
{
    return __sync_fetch_and_add(Addend, Value);
}

static inline short InterlockedExchangeAdd16(volatile short *Addend, short Value)
{
    return __sync_fetch_and_add(Addend, Value);
}

static inline __cdecl int InterlockedExchangeAdd(volatile int *Addend, int Value)
{
    return __sync_fetch_and_add(Addend, Value);
}

static inline char InterlockedAnd8(volatile char *value, char mask)
{
    return __sync_fetch_and_and(value, mask);
}

static inline short InterlockedAnd16(volatile short *value, short mask)
{
    return __sync_fetch_and_and(value, mask);
}

static inline int InterlockedAnd(volatile int *value, int mask)
{
    return __sync_fetch_and_and(value, mask);
}

static inline char InterlockedOr8(volatile char *value, char mask)
{
    return __sync_fetch_and_or(value, mask);
}

static inline short InterlockedOr16(volatile short *value, short mask)
{
    return __sync_fetch_and_or(value, mask);
}

static inline int InterlockedOr(volatile int *value, int mask)
{
    return __sync_fetch_and_or(value, mask);
}

static inline char InterlockedXor8(volatile char *value, char mask)
{
    return __sync_fetch_and_xor(value, mask);
}

static inline short InterlockedXor16(volatile short *value, short mask)
{
    return __sync_fetch_and_xor(value, mask);
}

static inline int InterlockedXor(volatile int *value, int mask)
{
    return __sync_fetch_and_xor(value, mask);
}

static inline short InterlockedIncrement16(volatile short *lpAddend)
{
    return __sync_add_and_fetch(lpAddend, 1);
}

static inline __cdecl int InterlockedIncrement(volatile int *lpAddend)
{
    return __sync_add_and_fetch(lpAddend, 1);
}

static inline short InterlockedDecrement16(volatile short *lpAddend)
{
    return __sync_sub_and_fetch(lpAddend, 1);
}

static inline __cdecl int InterlockedDecrement(volatile int *lpAddend)
{
    return __sync_sub_and_fetch(lpAddend, 1);
}

static inline long long InterlockedCompareExchange64(volatile long long *Destination,
						     long long Exchange,
						     long long Comperand)
{
    return __sync_val_compare_and_swap(Destination, Comperand, Exchange);
}

#ifdef _WIN64
static inline unsigned char InterlockedCompareExchange128(long long volatile *Destination,
							  long long ExchangeHigh,
							  long long ExchangeLow,
							  long long *ComparandResult)
{
    long long xchg[2] = { ExchangeLow, ExchangeHigh };
    return __sync_bool_compare_and_swap((__uint128_t *)Destination,
					*((__uint128_t *)ComparandResult),
					*((__uint128_t *)xchg));
}
#endif

static inline long long InterlockedExchange64(volatile long long *Target, long long Value)
{
    /* NOTE: __sync_lock_test_and_set would be an acquire barrier, so we force a full barrier */
    __sync_synchronize();
    return __sync_lock_test_and_set(Target, Value);
}

static inline long long InterlockedExchangeAdd64(volatile long long *Addend, long long Value)
{
    return __sync_fetch_and_add(Addend, Value);
}

static inline long long InterlockedAnd64(volatile long long *value, long long mask)
{
    return __sync_fetch_and_and(value, mask);
}

static inline long long InterlockedOr64(volatile long long *value, long long mask)
{
    return __sync_fetch_and_or(value, mask);
}

static inline long long InterlockedXor64(volatile long long *value, long long mask)
{
    return __sync_fetch_and_xor(value, mask);
}

static inline long long InterlockedIncrement64(volatile long long *lpAddend)
{
        return __sync_add_and_fetch(lpAddend, 1);
}

static inline long long InterlockedDecrement64(volatile long long *lpAddend)
{
    return __sync_sub_and_fetch(lpAddend, 1);
}

#ifdef _MSC_VER
#if defined(_M_IX86) || defined(_M_AMD64) || defined(_M_ARM64)
#define __ACQ_(x) x
#define __REL_(x) x
#define __NF_(x) x
#else
#error "Unsupported architecture"
#endif

#define InterlockedBitTestAndSet _interlockedbittestandset
#define InterlockedBitTestAndSetAcquire __ACQ_(_interlockedbittestandset)
#define InterlockedBitTestAndSetRelease __REL_(_interlockedbittestandset)
#define InterlockedBitTestAndSetNoFence __NF_(_interlockedbittestandset)

#define InterlockedBitTestAndReset _interlockedbittestandreset
#define InterlockedBitTestAndResetAcquire __ACQ_(_interlockedbittestandreset)
#define InterlockedBitTestAndResetRelease __REL_(_interlockedbittestandreset)
#define InterlockedBitTestAndResetNoFence __NF_(_interlockedbittestandreset)

#ifdef _WIN64
#define InterlockedBitTestAndSet64 _interlockedbittestandset64
#define InterlockedBitTestAndSet64Acquire __ACQ_(_interlockedbittestandset64)
#define InterlockedBitTestAndSet64Release __REL_(_interlockedbittestandset64)
#define InterlockedBitTestAndSet64NoFence __NF_(_interlockedbittestandset64)

#define InterlockedBitTestAndReset64 _interlockedbittestandreset64
#define InterlockedBitTestAndReset64Acquire __ACQ_(_interlockedbittestandreset64)
#define InterlockedBitTestAndReset64Release __REL_(_interlockedbittestandreset64)
#define InterlockedBitTestAndReset64NoFence __NF_(_interlockedbittestandreset64)

#define InterlockedBitTestAndSetPointer(ptr, val) \
    InterlockedBitTestAndSet64((PLONGLONG)ptr, (LONGLONG)val)
#define InterlockedAddPointer(ptr, val) InterlockedAdd64((PLONGLONG)ptr, (LONGLONG)val)
#define InterlockedAndPointer(ptr, val) InterlockedAnd64((PLONGLONG)ptr, (LONGLONG)val)
#define InterlockedOrPointer(ptr, val) InterlockedOr64((PLONGLONG)ptr, (LONGLONG)val)
#else
#define InterlockedBitTestAndSetPointer(ptr, val) \
    InterlockedBitTestAndSet((volatile long *)ptr, (LONG)val)
#define InterlockedAddPointer(ptr, val) InterlockedAdd((PLONG)ptr, (LONG)val)
#define InterlockedAndPointer(ptr, val) InterlockedAnd((PLONG)ptr, (LONG)val)
#define InterlockedOrPointer(ptr, val) InterlockedOr((PLONG)ptr, (LONG)val)
#endif /* _WIN64 */

#define InterlockedExchangeAcquire16 __ACQ_(InterlockedExchange16)
#define InterlockedExchangeNoFence16 __NF_(InterlockedExchange16)

#define InterlockedExchangeAcquire __ACQ_(InterlockedExchange)
#define InterlockedExchangeNoFence __NF_(InterlockedExchange)

#define InterlockedExchangeAcquire64 __ACQ_(InterlockedExchange64)
#define InterlockedExchangeNoFence64 __NF_(InterlockedExchange64)

#define InterlockedExchangePointerAcquire __ACQ_(InterlockedExchangePointer)
#define InterlockedExchangePointerNoFence __NF_(InterlockedExchangePointer)

#endif /* _MSC_VER */

#if defined(_M_IX86) || defined(_M_AMD64)

/*
 * Yields processor time
 */
static inline void _mm_pause(void)
{
    __asm__ __volatile__("pause" : : : "memory");
}

/*
 * 64-bit maths
 */
static inline long long __emul(int a, int b)
{
    long long retval;
    __asm__("imull %[b]" : "=A" (retval) : [a] "a" (a), [b] "rm" (b));
    return retval;
}

static inline unsigned long long __emulu(unsigned int a, unsigned int b)
{
    unsigned long long retval;
    __asm__("mull %[b]" : "=A" (retval) : [a] "a" (a), [b] "rm" (b));
    return retval;
}

/*
 * Bit manipulation
 */

static inline unsigned char BitScanForward(unsigned int *Index,
					   unsigned int Mask)
{
    __asm__("bsfl %[Mask], %[Index]" :
	    [Index] "=r" (*Index) : [Mask] "mr" (Mask));
    return Mask ? 1 : 0;
}

static inline unsigned char BitScanReverse(unsigned int *Index,
					   unsigned int Mask)
{
    __asm__("bsrl %[Mask], %[Index]" :
	    [Index] "=r" (*Index) : [Mask] "mr" (Mask));
    return Mask ? 1 : 0;
}

/*
 * System information
*/
void __cpuid(int CPUInfo[4], int InfoType);
void __cpuidex(int CPUInfo[4], int InfoType, int ECXValue);

#endif	/* defined(_M_IX86) || defined(_M_AMD64) */

#ifdef _M_IX86

/*
 * TLS base register routines
 */

static inline unsigned char __readfsbyte(unsigned long offset)
{
    unsigned char value;
    __asm__ __volatile__("movb %%fs:%a[offset], %b[value]" :
			 [value] "=q" (value) : [offset] "ir" (offset));
    return value;
}

static inline unsigned short __readfsword(unsigned long offset)
{
    unsigned short value;
    __asm__ __volatile__("movw %%fs:%a[offset], %w[value]" :
			 [value] "=r" (value) : [offset] "ir" (offset));
    return value;
}

static inline unsigned long __readfsdword(unsigned long offset)
{
    unsigned long value;
    __asm__ __volatile__("movl %%fs:%a[offset], %k[value]" :
			 [value] "=r" (value) : [offset] "ir" (offset));
    return value;
}

/*
 * Bit manipulation
 */

/*
  NOTE: in __ll_lshift, __ll_rshift and __ull_rshift we use the "A"
  constraint (edx:eax) for the Mask argument, because it's the only way GCC
  can pass 64-bit operands around - passing the two 32 bit parts separately
  just confuses it. Also we declare Bit as an int and then truncate it to
  match Visual C++ behavior
*/
static inline unsigned long long __ll_lshift(unsigned long long Mask, int Bit)
{
    unsigned long long retval = Mask;

    __asm__("shldl %b[Bit], %%eax, %%edx; sall %b[Bit], %%eax" :
	    "+A" (retval) :
	    [Bit] "Nc" ((unsigned char)((unsigned long)Bit) & 0xFF));

    return retval;
}

static inline long long __ll_rshift(long long Mask, int Bit)
{
    long long retval = Mask;

    __asm__("shrdl %b[Bit], %%edx, %%eax; sarl %b[Bit], %%edx" :
	    "+A" (retval) :
	    [Bit] "Nc" ((unsigned char)((unsigned long)Bit) & 0xFF));

    return retval;
}

static inline unsigned long long __ull_rshift(unsigned long long Mask, int Bit)
{
    unsigned long long retval = Mask;

    __asm__("shrdl %b[Bit], %%edx, %%eax; shrl %b[Bit], %%edx" :
	    "+A" (retval) :
	    [Bit] "Nc" ((unsigned char)((unsigned long)Bit) & 0xFF));

    return retval;
}

#elif defined(_M_AMD64)

/*
 * TLS base register routines
 */

static inline unsigned char __readgsbyte(unsigned long offset)
{
    unsigned char value;
    __asm__ __volatile__("movb %%gs:%a[offset], %b[value]" :
			 [value] "=r" (value) : [offset] "ir" (offset));
    return value;
}

static inline unsigned short __readgsword(unsigned long offset)
{
    unsigned short value;
    __asm__ __volatile__("movw %%gs:%a[offset], %w[value]" :
			 [value] "=r" (value) : [offset] "ir" (offset));
    return value;
}

static inline unsigned long __readgsdword(unsigned long offset)
{
    unsigned long value;
    __asm__ __volatile__("movl %%gs:%a[offset], %k[value]" :
			 [value] "=r" (value) : [offset] "ir" (offset));
    return value;
}

static inline unsigned long long __readgsqword(unsigned long offset)
{
    unsigned long long value;
    __asm__ __volatile__("movq %%gs:%a[offset], %q[value]" :
			 [value] "=r" (value) : [offset] "ir" (offset));
    return value;
}

/*
 * String manipulation
 */
static inline void __stosq(unsigned long long *Dest,
			   unsigned long long Data,
			   size_t Count)
{
    __asm__ __volatile__("rep; stosq" :
			 [Dest] "=D" (Dest), [Count] "=c" (Count) :
			 "[Dest]" (Dest), "a" (Data), "[Count]" (Count));
}

/*
 * Bit manipulation
 */
static inline unsigned char BitScanForward64(unsigned long long *Index,
					     unsigned long long Mask)
{
    unsigned long long Index64;
    __asm__("bsfq %[Mask], %[Index]" :
	    [Index] "=r" (Index64) : [Mask] "mr" (Mask));
    *Index = Index64;
    return Mask ? 1 : 0;
}

static inline unsigned char BitScanReverse64(unsigned long long *Index,
					     unsigned long long Mask)
{
    unsigned long long Index64;
    __asm__("bsrq %[Mask], %[Index]" :
	    [Index] "=r" (Index64) : [Mask] "mr" (Mask));
    *Index = Index64;
    return Mask ? 1 : 0;
}

static inline long long __ll_rshift(long long Mask, int Bit)
{
    long long retval;
    unsigned char shift = Bit & 0x3F;

    __asm__("sarq %[shift], %[Mask]" : "=r"(retval) :
	    [Mask] "0"(Mask), [shift] "c"(shift));

    return retval;
}

static inline unsigned long long __ull_rshift(unsigned long long Mask, int Bit)
{
    long long retval;
    unsigned char shift = Bit & 0x3F;

    __asm__("shrq %[shift], %[Mask]" : "=r"(retval) :
	    [Mask] "0"(Mask), [shift] "c"(shift));

    return retval;
}

static inline unsigned char _bittest64(const long long *a, long long b)
{
    unsigned char retval;

    if(__builtin_constant_p(b)) {
	__asm__("bt %[b], %[a]; setb %b[retval]" : [retval] "=q" (retval) :
		[a] "mr" (*(a + (b / 64))), [b] "Ir" (b % 64));
    } else {
	__asm__("bt %[b], %[a]; setb %b[retval]" : [retval] "=q" (retval) :
		[a] "m" (*a), [b] "r" (b));
    }

    return retval;
}
#define BitTest64 _bittest64

static inline unsigned long long __ll_lshift(unsigned long long Mask, int Bit)
{
    unsigned long long retval;
    unsigned char shift = Bit & 0x3F;

    __asm__("shlq %[shift], %[Mask]" : "=r"(retval) :
	    [Mask] "0"(Mask), [shift] "c"(shift));

    return retval;
}

static inline void __faststorefence(void)
{
    long local;
    __asm__ __volatile__("lock; orl $0, %0;" : : "m"(local));
}

#elif defined(_M_ARM64)

#define _ReadWriteBarrier() __sync_synchronize()

unsigned __int64 __getReg(int);

static inline void __yield(void)
{
    __asm__ __volatile__("yield");
}

static inline void __break(unsigned int value)
{
    __asm__ __volatile__("bkpt %0" : : "M"(value));
}

static inline unsigned short _byteswap_ushort(unsigned short value)
{
    return (value >> 8) | (value << 8);
}

static inline unsigned _CountLeadingZeros(int Mask)
{
    return Mask ? __builtin_clz(Mask) : 32;
}

static inline unsigned _CountTrailingZeros(int Mask)
{
    return Mask ? __builtin_ctz(Mask) : 32;
}

static inline unsigned char BitScanForward(unsigned int *const Index,
					   const unsigned int Mask)
{
    *Index = __builtin_ctz(Mask);
    return Mask ? 1 : 0;
}

static inline unsigned char BitScanForward64(unsigned long long *const Index,
					     const unsigned long long Mask)
{
    *Index = __builtin_ctz(Mask);
    return Mask ? 1 : 0;
}

static inline unsigned char BitScanReverse(unsigned int *const Index,
					   const unsigned int Mask)
{
    *Index = 31 - __builtin_clz(Mask);
    return Mask ? 1 : 0;
}

static inline unsigned char BitScanReverse64(unsigned long long *const Index,
					   const unsigned long long Mask)
{
    *Index = 63 - __builtin_clz(Mask);
    return Mask ? 1 : 0;
}

/* Read the CNTVCT cpu system register which provides a consistent value of
 * the virtual system counter across the system */
static inline unsigned long long __rdtsc() {
    unsigned long long cntvct;
    asm volatile ("mrs %0, cntvct_el0; " : "=r"(cntvct));
    return cntvct;
}

#else
#error "Unsupported architecture"
#endif
