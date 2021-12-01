#pragma once

#include <ntos.h>

/* Conversion functions */
#define BCD_INT(bcd)				\
    (((bcd & 0xF0) >> 4) * 10 + (bcd & 0x0F))
#define INT_BCD(int)				\
    (UCHAR)(((int / 10) << 4) + (int % 10))
