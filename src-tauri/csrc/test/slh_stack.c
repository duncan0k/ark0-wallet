/*
 * Whether SK.seed or SK.prf is left on the stack after key generation or signing through the wallet's
 * wrapper (pqw_slhdsa128s.c), and how deep the calls go. The stack below main is painted with a pattern,
 * the call is made, and the same region is searched. Used by scripts/check-stack-wipe.sh; exits 0 when no
 * secret is found.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
int pqw_slhdsa128s_keypair(uint8_t *pk, uint8_t *sk, const uint8_t *seed);
int pqw_slhdsa128s_sign(uint8_t *sig, const uint8_t *m, size_t mlen, const uint8_t *ctx, size_t ctxlen, const uint8_t *sk, const uint8_t *addrnd);
#define N (256 * 1024)
#if defined(_MSC_VER)
#define PQW_TEST_NOINLINE __declspec(noinline)
#else
#define PQW_TEST_NOINLINE __attribute__((noinline))
#endif
/* One function both paints (mode 0) and scans (mode 1), so that its buffer sits at the same addresses. */
PQW_TEST_NOINLINE size_t region(int mode, const uint8_t *needle, size_t nl, int *found) {
  volatile uint8_t b[N]; size_t deepest = 0;
  if (mode == 0) { for (size_t i = 0; i < N; i++) b[i] = 0xA5; return 0; }
  *found = 0;
  for (size_t i = 0; i < N; i++) if (b[i] != 0xA5) { deepest = N - i; break; }
  for (size_t i = 0; i + nl <= N; i++) { size_t j; for (j = 0; j < nl && b[i + j] == needle[j]; j++); if (j == nl) { *found = 1; break; } }
  return deepest;
}
static uint8_t sig[7856];
static int left = 0;
int main(void) {
  uint8_t seed[48], pk[32], sk[64], m[32] = {1};
  for (int i = 0; i < 48; i++) seed[i] = (uint8_t)(0x40 + i);
  int f;
  region(0, 0, 0, 0); pqw_slhdsa128s_keypair(pk, sk, seed); size_t d = region(1, seed, 16, &f);
  printf("keygen: deepest %zu bytes, SK.seed left on the stack: %s\n", d, f ? "yes" : "no"); left |= f;
  region(0, 0, 0, 0); pqw_slhdsa128s_keypair(pk, sk, seed); d = region(1, seed + 16, 16, &f);
  printf("keygen: SK.prf left: %s\n", f ? "yes" : "no"); left |= f;
  region(0, 0, 0, 0); pqw_slhdsa128s_sign(sig, m, 32, (const uint8_t *)"P2MR/SLHDSA128S/EXP0", 20, sk, NULL); d = region(1, seed, 16, &f);
  printf("sign: deepest %zu bytes, SK.seed left: %s\n", d, f ? "yes" : "no"); left |= f;
  region(0, 0, 0, 0); pqw_slhdsa128s_sign(sig, m, 32, (const uint8_t *)"P2MR/SLHDSA128S/EXP0", 20, sk, NULL); d = region(1, seed + 16, 16, &f);
  printf("sign: SK.prf left: %s\n", f ? "yes" : "no"); left |= f;
  return left;
}
