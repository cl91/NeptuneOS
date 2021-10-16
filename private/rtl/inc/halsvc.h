#pragma once

#include <services.h>
#include <halsvc_gen.h>

compile_assert(TOO_MANY_HAL_SERVICES, NUMBER_OF_HAL_SERVICES < 0x1000UL);
