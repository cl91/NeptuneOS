/*
 * Copyright 2017, DornerWorks
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * This data was produced by DornerWorks, Ltd. of Grand Rapids, MI, USA under
 * a DARPA SBIR, Contract Number D16PC00107.
 *
 * Approved for Public Release, Distribution Unlimited.
 *
 */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint64_t len;    /* processed message length */
    uint32_t h[4];   /* hash state */
    uint8_t buf[64]; /* message block buffer */
} md5_t;

void md5_init(md5_t *s);
void md5_sum(md5_t *s, uint8_t *md);
void md5_update(md5_t *s, const void *m, unsigned long len);

#ifdef __cplusplus
}
#endif

