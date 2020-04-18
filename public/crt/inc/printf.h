#pragma once
#include <stdarg.h>
#include <stdint.h>

int scnprintf(char *buf, size_t size, const char *fmt, ...);
int snprintf(char *buf, size_t size, const char *fmt, ...);
int vscnprintf(char *buf, size_t size, const char *fmt, va_list args);
int vsnprintf(char *buf, size_t size, const char *fmt, va_list args);
