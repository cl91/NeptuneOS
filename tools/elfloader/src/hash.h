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

#include "crypt_sha256.h"
#include "crypt_md5.h"
#include <types.h>

/* enum to store the hashing methods */
enum hash_methods {
    SHA_256,
    MD5
};

/* Structure that contains a structure for each hash type and an integer
 * representation of the hashing method used
 */
typedef struct {
    sha256_t sha_structure;
    md5_t md5_structure;
    unsigned int hash_type;
} hashes_t;

void get_hash(
    hashes_t hashes,
    const void *data,
    size_t len,
    void *outputted_hash);

void print_hash(
    void const *hash,
    size_t len);

