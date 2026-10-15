/*
 * Build configuration of the vendored mldsa-native library for pq-wallet.
 *
 * ML-DSA-44 only, with key generation, signing and verification. No native backend is enabled: the
 * portable C code is the only implementation on every platform, as in the Ark-0 node, whose consensus
 * code compiles this same library (verification only).
 *
 * Randomness for hedged signing comes from pqw_randombytes(), implemented in Rust on top of the operating
 * system's generator (src/mldsa.rs). With MLD_CONFIG_CUSTOM_RANDOMBYTES set, src/randombytes.h leaves
 * mld_randombytes() to this file.
 */
#ifndef PQW_MLDSA44_CONFIG_H
#define PQW_MLDSA44_CONFIG_H

#define MLD_CONFIG_PARAMETER_SET 44
#define MLD_CONFIG_NAMESPACE_PREFIX pqw_mldsa
#define MLD_CONFIG_CUSTOM_RANDOMBYTES

#include "mldsa_native_config.h"

#if !defined(__ASSEMBLER__)
#include <stddef.h>
#include <stdint.h>

#if defined(_MSC_VER) && !defined(__clang__)
#define PQW_INLINE __inline
#else
#define PQW_INLINE inline
#endif

/* Fills out[0..outlen) from the operating system's generator; returns 0 on success, nonzero on failure,
 * in which case signing fails rather than continuing with predictable randomness. */
int pqw_randombytes(uint8_t *out, size_t outlen);

static PQW_INLINE int mld_randombytes(uint8_t *out, size_t outlen)
{
    return pqw_randombytes(out, outlen);
}
#endif /* !__ASSEMBLER__ */

#endif /* PQW_MLDSA44_CONFIG_H */
