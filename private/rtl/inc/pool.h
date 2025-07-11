#pragma once

#include <services.h>
#include <util.h>

/*
 * Two machine words for smallest RTL_POOL_BLOCK. The unused lowest RTL_POOL_BLOCK_SHIFT
 * bits are used by the Object Manager to encode the flags of the global handle.
 */
#define RTL_POOL_BLOCK_SHIFT	(1 + MWORD_LOG2SIZE)
#define RTL_POOL_SMALLEST_BLOCK	(1ULL << RTL_POOL_BLOCK_SHIFT)
