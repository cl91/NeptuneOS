/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <devices_gen.h>
#include <drivers/common.h>
#include <mode/arm_generic_timer.h>

#include <elfloader_common.h>


static int generic_timer_init(UNUSED struct elfloader_device *dev, UNUSED void *match_data)
{
    reset_cntvoff();
    return 0;
}

static const struct dtb_match_table generic_timer_matches[] = {
    { .compatible = "arm,armv7-timer" },
    { .compatible = "arm,armv8-timer" },
    { .compatible = NULL /* sentinel */ },
};

static const struct elfloader_driver generic_timer = {
    .match_table = generic_timer_matches,
    .type = DRIVER_TIMER,
    .init = &generic_timer_init,
    .init_on_secondary_cores = &generic_timer_init,
    .ops = NULL,
};

ELFLOADER_DRIVER(generic_timer);
