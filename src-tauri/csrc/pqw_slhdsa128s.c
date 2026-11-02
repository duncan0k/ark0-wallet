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

/*
 * Key generation and signing copy SK.seed and SK.prf into a slh_var_t on the stack, and slhdsa-c returns
 * without wiping it. After each of those calls the wrapper writes zeros over this many bytes of stack below
 * its own frame, where the library's frames were. Measured (stack painted with a pattern, then searched for
 * the deepest changed byte): 3.9 to 5.1 KB for key generation and signing with gcc and clang at -O0 and
 * -O2; gcc's -fstack-usage gives 2,576 bytes for xmss_node, 2,544 for wots_pk_from_sig and 768 for slh_sign
 * as the largest frames. 16 KiB is about three times the deepest measured use.
 */
#define PQW_SLH_WIPE_BYTES (16 * 1024)

#if defined(_MSC_VER)
#define PQW_NOINLINE __declspec(noinline)
#else
#define PQW_NOINLINE __attribute__((noinline))
#endif

/* Zeros over a local buffer, through a volatile pointer so that no store is left out; never inlined, so
 * that the buffer lies below the caller's frame, over the stack the library used. */
PQW_NOINLINE void pqw_slhdsa128s_wipe_stack(void)
{
  uint8_t buf[PQW_SLH_WIPE_BYTES];
  volatile uint8_t *p = buf;
  size_t i;
  for (i = 0; i < sizeof buf; i++)
  {
    p[i] = 0;
  }
}

/* Zeros over a buffer of the wrapper's own, through a volatile pointer. */
static void pqw_wipe(void *buf, size_t n)
{
  volatile uint8_t *p = (volatile uint8_t *)buf;
  size_t i;
  for (i = 0; i < n; i++)
  {
    p[i] = 0;
  }
}

/* pk: 32 bytes, sk: 64 bytes, seed: 48 bytes (SK.seed || SK.prf || PK.seed). 0 on success. */
int pqw_slhdsa128s_keypair(uint8_t *pk, uint8_t *sk, const uint8_t *seed)
{
  if (slh_pk_sz(&slh_dsa_sha2_128s) != PQW_SLH_PK || slh_sk_sz(&slh_dsa_sha2_128s) != PQW_SLH_SK)
  {
    return -1;
  }
  {
    int rc = slh_keygen_internal(sk, pk, seed, seed + PQW_SLH_N, seed + 2 * PQW_SLH_N, &slh_dsa_sha2_128s);
    pqw_slhdsa128s_wipe_stack();
    return rc;
  }
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
  {
    size_t n = slh_sign(sig, m, mlen, ctx, ctxlen, sk, addrnd, &slh_dsa_sha2_128s);
    pqw_slhdsa128s_wipe_stack();
    if (n != PQW_SLH_SIG)
    {
      pqw_wipe(sig, PQW_SLH_SIG);
      return -1;
    }
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
