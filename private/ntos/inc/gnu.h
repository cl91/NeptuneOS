#pragma once

#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)
#define __aligned(x)    __attribute__ ((aligned(x)))
#define __packed         __attribute__((__packed__))
