/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#pragma once

struct elfloader_device;
struct elfloader_driver;

typedef int (*driver_init_t)(struct elfloader_device *dev, void *match_data);

/*
 * Each driver has an array of dtb_match_tables.
 * The last entry in the array should have compatible = NULL,
 * all others contain a compatible string that the driver accepts.
 * The match_data pointer will be passed to the driver's init() function.
 */
struct dtb_match_table {
    const char *compatible;
    void *match_data;
};

enum driver_type {
    DRIVER_INVALID = 0,
    DRIVER_SMP,
    DRIVER_UART,
    DRIVER_TIMER,
    DRIVER_MAX
};

struct elfloader_driver {
    const struct dtb_match_table *match_table;
    enum driver_type type;
    driver_init_t init;
    driver_init_t init_on_secondary_cores;
    /* ops struct, type depends on driver type. */
    const void *ops;
};


extern struct elfloader_driver *__start__driver_list[];
extern struct elfloader_driver *__stop__driver_list[];

#define ELFLOADER_DRIVER(_name) \
    const struct elfloader_driver *_driver_list_##_name \
        __attribute__((unused,section("_driver_list"))) = &_name;
