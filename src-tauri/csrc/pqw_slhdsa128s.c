/*
 * SLH-DSA-SHA2-128s through the vendored slhdsa-c (slhdsa-c/): the three calls the wallet makes, with the
 * sizes of this one parameter set fixed here, so that the Rust side passes buffers of exactly these sizes
 * and the library is never called with a length it has not been checked for.
 *
 * Pure SLH-DSA (FIPS 205 Algorithms 22 and 24, the external interface with a context string); key
 * generation from the three 16-byte seeds (Algorithm 18, slh_keygen_internal).
 */
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "slhdsa-c/slh_dsa.h"

#define PQW_SLH_N 16
#define PQW_SLH_PK 32
#define PQW_SLH_SK 64
#define PQW_SLH_SIG 7856
#define PQW_SLH_CTX_MAX 255

/* pk: 32 bytes, sk: 64 bytes, seed: 48 bytes (SK.seed || SK.prf || PK.seed). 0 on success. */
int pqw_slhdsa128s_keypair(uint8_t *pk, uint8_t *sk, const uint8_t *seed)
{
  if (slh_pk_sz(&slh_dsa_sha2_128s) != PQW_SLH_PK || slh_sk_sz(&slh_dsa_sha2_128s) != PQW_SLH_SK)
  {
    return -1;
  }
  return slh_keygen_internal(sk, pk, seed, seed + PQW_SLH_N, seed + 2 * PQW_SLH_N, &slh_dsa_sha2_128s);
}

/*
 * sig: 7856 bytes; addrnd: 16 bytes of fresh randomness (opt_rand), or NULL for the deterministic
 * variant (opt_rand = PK.seed). 0 on success.
 */
int pqw_slhdsa128s_sign(uint8_t *sig, const uint8_t *m, size_t mlen, const uint8_t *ctx, size_t ctxlen,
                        const uint8_t *sk, const uint8_t *addrnd)
{
  if (ctxlen > PQW_SLH_CTX_MAX || slh_sig_sz(&slh_dsa_sha2_128s) != PQW_SLH_SIG)
  {
    return -1;
  }
  if (slh_sign(sig, m, mlen, ctx, ctxlen, sk, addrnd, &slh_dsa_sha2_128s) != PQW_SLH_SIG)
  {
    memset(sig, 0, PQW_SLH_SIG);
    return -1;
  }
  return 0;
}

/* sig: exactly 7856 bytes, pk: 32 bytes (the lengths are fixed before the library reads either). 0 if valid. */
int pqw_slhdsa128s_verify(const uint8_t *sig, const uint8_t *m, size_t mlen, const uint8_t *ctx, size_t ctxlen,
                          const uint8_t *pk)
{
  if (ctxlen > PQW_SLH_CTX_MAX)
  {
    return -1;
  }
  return slh_verify(m, mlen, sig, PQW_SLH_SIG, ctx, ctxlen, pk, &slh_dsa_sha2_128s) == 1 ? 0 : -1;
}
