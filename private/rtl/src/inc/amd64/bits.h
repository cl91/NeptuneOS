#pragma once

#define BITS_PER_LONG_LONG (64)

#ifdef _WIN32
#define BITS_PER_LONG (32)
#else
#define BITS_PER_LONG (64)
#endif
