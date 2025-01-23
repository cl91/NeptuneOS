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

#include <printf.h>
#include <types.h>

#include "../hash.h"

/* Function to perform all hash operations.
 *
 * The outputted hash is stored in the outputted_hash pointer after the "sum"
 * operation is used. This way beats having a bunch of #ifdefs in the source
 * code, and is scalable to any other hashing algorithm.
 */
void get_hash(
    hashes_t hashes,
    const void *data,
    size_t len,
    void *outputted_hash)
{
    if (hashes.hash_type == SHA_256) {
        sha256_t calculated_hash = hashes.sha_structure;
        sha256_init(&calculated_hash);
        sha256_update(&calculated_hash, data, len);
        sha256_sum(&calculated_hash, outputted_hash);
    } else {
        md5_t calculated_hash = hashes.md5_structure;
        md5_init(&calculated_hash);
        md5_update(&calculated_hash, data, len);
        md5_sum(&calculated_hash, outputted_hash);
    }
}

/* Function to print the hash */
void print_hash(
    void const *hash,
    size_t len)
{
    uint8_t const *hash_bytes = hash;
    for (size_t i = 0; i < len; i++) {
        printf("%02x", hash_bytes[i]);
    }
    printf("\n");
}
