/*
 * Known answers for the SLH-DSA-SHA2-128s build of slhdsa-c, from p2mr-ts with @noble/post-quantum (an
 * independent implementation): the public key of a fixed seed, and the SHA-256 of a deterministic
 * signature. A wrong byte order changes both. Used by scripts/check-byte-order.sh; exits 0 when both match.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>

int pqw_slhdsa128s_keypair(uint8_t *pk, uint8_t *sk, const uint8_t *seed);
int pqw_slhdsa128s_sign(uint8_t *sig, const uint8_t *m, size_t mlen, const uint8_t *ctx, size_t ctxlen, const uint8_t *sk, const uint8_t *addrnd);
/* The portable SHA-256 of slhdsa-c (sha2_256.c). */
void sha2_256(uint8_t *md, const void *m, size_t m_sz);

static void unhex(uint8_t *out, const char *hex)
{
  size_t i;
  for (i = 0; hex[2 * i]; i++) {
    unsigned v;
    sscanf(hex + 2 * i, "%2x", &v);
    out[i] = (uint8_t)v;
  }
}

static void tohex(char *out, const uint8_t *in, size_t n)
{
  size_t i;
  for (i = 0; i < n; i++) sprintf(out + 2 * i, "%02x", in[i]);
}

int main(void)
{
  /* Key B of p2mr-ts's M4 vectors (p2mr_m4_pq2_construction.json) and its deterministic signature over
   * the pq2 spend's message (p2mr_m4_pq2_spend.json, case pq2_slhdsa128s_default). */
  static const char *seed_hex = "02d8ae9f631f168961bee809f50a64e37c6c3bd0f222dc289946b6bd5a2246678a01c204fb7af8f5fc9da3a8f9c62a6d";
  static const char *pk_want = "8a01c204fb7af8f5fc9da3a8f9c62a6d7c89185b287f18e53e93c2e7b7ec3c17";
  static const char *msg_hex = "2ff4487eee01ffc57e04b3f20f5cc0887523a609c218f823af7057cc46577d1f";
  static const char *sig_sha_want = "f46d95ecffe77ea332b7b56ba67036677b24e4a962ea5b837cd5d99a02ce4bc9";
  static const char ctx[] = "P2MR/SLHDSA128S/EXP0";
  uint8_t seed[48], pk[32], sk[64], msg[32], md[32];
  static uint8_t sig[7856];
  char hex[65];
  int ok = 1;

  unhex(seed, seed_hex);
  unhex(msg, msg_hex);
  if (pqw_slhdsa128s_keypair(pk, sk, seed) != 0) return 2;
  tohex(hex, pk, 32);
  printf("public key %s %s\n", hex, strcmp(hex, pk_want) == 0 ? "ok" : "MISMATCH");
  ok &= strcmp(hex, pk_want) == 0;
  if (pqw_slhdsa128s_sign(sig, msg, 32, (const uint8_t *)ctx, 20, sk, NULL) != 0) return 2;
  sha2_256(md, sig, sizeof sig);
  tohex(hex, md, 32);
  printf("signature sha256 %s %s\n", hex, strcmp(hex, sig_sha_want) == 0 ? "ok" : "MISMATCH");
  ok &= strcmp(hex, sig_sha_want) == 0;
  return ok ? 0 : 1;
}
