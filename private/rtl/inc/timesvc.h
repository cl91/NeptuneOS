#include <nt.h>

/*
 * System time is defined as the time since the midnight of January 1, 1601,
 * measured in units of 100 nano-seconds.
 */
typedef struct _SYSTEM_TIME {
    ULONG64 SystemTime;
} SYSTEM_TIME, *PSYSTEM_TIME;

/*
 * Interrupt time refers to the time in unit of 100ns since the system boot.
 */
typedef struct _INTERRUPT_TIME {
    ULONG64 InterruptTime;
} INTERRUPT_TIME, *PINTERRUPT_TIME;

/*
 * Absolute counter time refers to the timestamp counter value at a given time.
 * The timestamp counter value is assumed to be stable, unaffected by sleep and
 * low power states, and synchronized across cores. We don't support systems that
 * do not meet this requirement.
 */
typedef struct _ABSOLUTE_COUNTER_TIME {
    ULONG64 CounterTime;
} ABSOLUTE_COUNTER_TIME, *PABSOLUTE_COUNTER_TIME;

/*
 * Relative counter time is the offset of the timestamp counter value since
 * system boot.
 */
typedef struct _RELATIVE_COUNTER_TIME {
    ULONG64 CounterTime;
} RELATIVE_COUNTER_TIME, *PRELATIVE_COUNTER_TIME;

/* The boot system time, recorded at the time of system initialization
 * (more specifically, when the KiInitTimer function is executing). This
 * is initialized from the system RTC (which we assume is in UTC). */
extern SYSTEM_TIME KiInitialSystemTime;

/* The initial TSC value (or CNTVCT value on arm64) at the time of system
 * initialization. This is assumed to correspond to KiInitialSystemTime. */
extern ABSOLUTE_COUNTER_TIME KiInitialCounterTime;

static inline SYSTEM_TIME KiInterruptTimeToSystemTime(IN INTERRUPT_TIME Time)
{
    return (SYSTEM_TIME) {
	.SystemTime = Time.InterruptTime + KiInitialSystemTime.SystemTime
    };
}

static inline INTERRUPT_TIME KiSystemTimeToInterruptTime(IN SYSTEM_TIME Time)
{
    return (INTERRUPT_TIME) {
	.InterruptTime = Time.SystemTime - min(KiInitialSystemTime.SystemTime, Time.SystemTime)
    };
}

static inline ABSOLUTE_COUNTER_TIME
KiRelativeCounterTimeToAbsoluteCounterTime(IN RELATIVE_COUNTER_TIME Time)
{
    return (ABSOLUTE_COUNTER_TIME) {
	.CounterTime = Time.CounterTime + KiInitialCounterTime.CounterTime
    };
}

static inline RELATIVE_COUNTER_TIME
KiAbsoluteCounterTimeToRelativeCounterTime(IN ABSOLUTE_COUNTER_TIME Time)
{
    return (RELATIVE_COUNTER_TIME) {
	.CounterTime = Time.CounterTime - min(KiInitialCounterTime.CounterTime, Time.CounterTime)
    };
}

#define TIME_MULTIPLIER_SHIFT	(32)
extern ULONG64 KiCounterTimeMultiplier;
extern ULONG64 KiInterruptTimeMultiplier;

static inline ULONG64 RtlMultiplyUlongByUlong(ULONG a, ULONG b)
{
	return (ULONG64)a * b;
}

/*
 * Returns (a * b) >> Shift
 */
static inline ULONG64 RtlMultiplyShift64(ULONG64 a, ULONG64 b, ULONG Shift)
{
    ULARGE_INTEGER rl, rm, rn, rh, a0, b0;
    ULONG64 c;

    a0.QuadPart = a;
    b0.QuadPart = b;

    rl.QuadPart = RtlMultiplyUlongByUlong(a0.LowPart, b0.LowPart);
    rm.QuadPart = RtlMultiplyUlongByUlong(a0.LowPart, b0.HighPart);
    rn.QuadPart = RtlMultiplyUlongByUlong(a0.HighPart, b0.LowPart);
    rh.QuadPart = RtlMultiplyUlongByUlong(a0.HighPart, b0.HighPart);

    /*
     * Each of these lines computes a 64-bit intermediate result into "c",
     * starting at bits 32-95.  The low 32-bits go into the result of the
     * multiplication, the high 32-bits are carried into the next step.
     */
    rl.HighPart = c = (ULONG64)rl.HighPart + rm.LowPart + rn.LowPart;
    rh.LowPart = c = (c >> 32) + rm.HighPart + rn.HighPart + rh.LowPart;
    rh.HighPart = (c >> 32) + rh.HighPart;

    /*
     * The 128-bit result of the multiplication is in rl.QuadPart and rh.QuadPart,
     * shift it right and throw away the high part of the result.
     */
    if (Shift == 0)
	return rl.QuadPart;
    if (Shift < 64)
	return (rl.QuadPart >> Shift) | (rh.QuadPart << (64 - Shift));
    return rh.QuadPart >> (Shift & 63);
}

/*
 * Here relative time counter refers to the TSC value minus the initial TSC
 * value recorded at system boot time (KiInitialCounterTime).
 */
static inline INTERRUPT_TIME KiRelativeCounterTimeToInterruptTime(IN RELATIVE_COUNTER_TIME Time)
{
    return (INTERRUPT_TIME) {
	.InterruptTime = RtlMultiplyShift64(Time.CounterTime,
					    KiCounterTimeMultiplier,
					    TIME_MULTIPLIER_SHIFT)
    };
}

static inline RELATIVE_COUNTER_TIME KiInterruptTimeToRelativeCounterTime(IN INTERRUPT_TIME Time)
{
    return (RELATIVE_COUNTER_TIME) {
	.CounterTime = RtlMultiplyShift64(Time.InterruptTime,
					  KiInterruptTimeMultiplier,
					  TIME_MULTIPLIER_SHIFT)
    };
}

static inline SYSTEM_TIME KiRelativeCounterTimeToSystemTime(IN RELATIVE_COUNTER_TIME Time)
{
    return KiInterruptTimeToSystemTime(KiRelativeCounterTimeToInterruptTime(Time));
}

static inline SYSTEM_TIME KiAbsoluteCounterTimeToSystemTime(IN ABSOLUTE_COUNTER_TIME Time)
{
    return KiRelativeCounterTimeToSystemTime(KiAbsoluteCounterTimeToRelativeCounterTime(Time));
}

static inline RELATIVE_COUNTER_TIME KiSystemTimeToRelativeCounterTime(IN SYSTEM_TIME Time)
{
    return KiInterruptTimeToRelativeCounterTime(KiSystemTimeToInterruptTime(Time));
}

static inline ABSOLUTE_COUNTER_TIME KiSystemTimeToAbsoluteCounterTime(IN SYSTEM_TIME Time)
{
    return KiRelativeCounterTimeToAbsoluteCounterTime(KiSystemTimeToRelativeCounterTime(Time));
}

#if defined(_M_IX86) || defined(_M_AMD64)
/* Use the ordered version of rdtsc to get an accurate time stamp counter. */
FORCEINLINE ABSOLUTE_COUNTER_TIME KiQueryAbsoluteCounterTime() {
    ULONG Unused;
    return (ABSOLUTE_COUNTER_TIME) { .CounterTime = __rdtscp(&Unused) };
}
#elif defined(_M_ARM64)
/* Read the CNTVCT cpu system register which provides a consistent value of
 * the virtual system counter across the system. */
FORCEINLINE ABSOLUTE_COUNTER_TIME KiQueryAbsoluteCounterTime() {
    ULONG64 VirtualTimerCounter;
    asm volatile ("mrs %0, cntvct_el0; " : "=r"(VirtualTimerCounter));
    return (ABSOLUTE_COUNTER_TIME) { .CounterTime = VirtualTimerCounter };
}
#else
#error "Unsupported architecture"
#endif

static inline RELATIVE_COUNTER_TIME KiQueryRelativeCounterTime()
{
    return KiAbsoluteCounterTimeToRelativeCounterTime(KiQueryAbsoluteCounterTime());
}

/*
 * System Timer Period (in units of 100ns). This is simply the conversion
 * factor between the TSC and the timer tick value reported by KeQueryTickCount.
 * The system does not actually have a periodic timer tick.
 */
#define TIMER_TICK_SHIFT		16
#define TIMER_RESOLUTION_IN_100NS	(1ULL << TIMER_TICK_SHIFT) /* 6.5536 ms */

static inline ULONG64 KiRelativeCounterTimeToTickCount(IN RELATIVE_COUNTER_TIME Time)
{
    return Time.CounterTime >> TIMER_TICK_SHIFT;
}
