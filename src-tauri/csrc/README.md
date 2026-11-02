# Vendored C code

`mldsa-native/` is [mldsa-native](https://github.com/pq-code-package/mldsa-native) v2.0.0, commit
`834a90d5e846ffa1e1611bd24e160bb2e9b86d35`, from the release tarball
`https://github.com/pq-code-package/mldsa-native/archive/refs/tags/v2.0.0.tar.gz`
(SHA-256 `97a7305c32b62cbcae97891823176e18ca96d9eaafc3728587d75bb113862a40`). It implements FIPS 204
(ML-DSA) and is licensed Apache-2.0 OR ISC OR MIT; see `mldsa-native/LICENSE`.

What was taken, unmodified: `LICENSE`, `mldsa/mldsa_native.c`, `mldsa/mldsa_native.h`,
`mldsa/mldsa_native_config.h`, and the `.c`, `.h` and `.inc` files of `mldsa/src/` and
`mldsa/src/fips202/`. These are byte-for-byte the files the Ark-0 Bitcoin Core patch series vendors in
`src/crypto/mldsa44/`, so the wallet signs with the same library the node verifies with.

What was left out: the assembly backends (`mldsa/src/native/`, `mldsa/src/fips202/native/`) and
everything outside `mldsa/`. Only the portable C code is built, on every platform.

What was added: `pqw_mldsa44_config.h` (ML-DSA-44, the `pqw_mldsa` symbol prefix, randomness from
`pqw_randombytes`) and `pqw_mldsa44.c` (the translation unit `build.rs` compiles).

`scripts/check-vendor.sh` re-downloads the release tarball, checks its SHA-256 and compares every
vendored file with it.

## slhdsa-c

`slhdsa-c/` is [slhdsa-c](https://github.com/pq-code-package/slhdsa-c) at commit
`a0fc1ff253930060d0246aebca06c2538eb92b88` (2025-07-22), the commit the Ark-0 nodes verify
OP_CHECKSLHDSA128S with. It implements FIPS 205 (SLH-DSA) and is licensed Apache-2.0 OR ISC OR MIT; see
`slhdsa-c/LICENSE`.

What was taken, unmodified: the SLH-DSA core and its SHA-2 instances with the library's own portable
SHA-2, the files the SHA2-128s parameter set needs:

| File | SHA-256 |
|---|---|
| `LICENSE` | `f5f353e7c2308465c5e82021a06acfba74d3d5e70d13e4af8226e9051a25ce2c` |
| `cbmc.h` | `91058b937e92736535be4c8372a6eae7cafd5ac00abc891476c7c23231c4cf80` |
| `plat_local.h` | `960145bea8fec1d21b00ffeaf5bb9de2aab8cb15b3ae22e8f847f5f44dfc594b` |
| `sha2_256.c` | `b1b74abe3d4b6b925ca4ce3ded43a5f2188f0f16a41f8ae91c93de95fc0fa07b` |
| `sha2_512.c` | `84b914b342a16d07716b1830668e3728892b422fc322f05fadec3993f60f2832` |
| `sha2_api.h` | `4315f4891acfdcadfdc220770fd3a8a080aec94f6346eec9d8badbea1bb3a6ba` |
| `slh_adrs.h` | `6a734cb673b12299165908f53fdade618d9005287b1a902de8ac90c211710d4c` |
| `slh_dsa.c` | `fbbf5c4ed4ea70bf9d90c1de4ddb168d5671e94621a708f110f57a81de0a5613` |
| `slh_dsa.h` | `aa5eb9234f9dc342d5a41af02a572fd68c4a832b05561cd4c95447a2be5cfe2e` |
| `slh_param.h` | `d848f41c5f5ac2b911d077209da0f9fb313ffcc8865c55b43dd09cdfce009ac7` |
| `slh_sha2.c` | `075066c5af445933868eeb42120451662aefd696cf5a4c71ce464fe758f07604` |
| `slh_sys.h` | `7280d918931f9302c7bd47043f477796102e777fa1d30ff667b479eb0fe9ae94` |
| `slh_var.h` | `0c87ae009a76c07f3c0c066b2d255e5f6cb18e6f38f7df3d805e395d37ef96b0` |

What was left out: the SHAKE instances and SHA-3 (`slh_shake.c`, `sha3_*`), HashSLH-DSA
(`slh_prehash.*`), and everything outside the repository's top directory (tests, proofs, build files).
`sha2_512.c` is there because the SHA-2 instances of the larger parameter sets, compiled in the same file
as SHA2-128s, refer to it; the wallet never calls them.

What was added: `pqw_slhdsa128s.c`, the wallet's wrapper: key generation from the three 16-byte seeds
(slh_keygen_internal), pure signing with a context string and 16 bytes of fresh randomness, and
verification, each for SLH-DSA-SHA2-128s only and with every buffer of a fixed size, so that the library
never reads a signature whose length has not been checked. `build.rs` compiles the five `.c` files as
plain C with the compiler's defaults, optimized in every profile.

`scripts/check-vendor.sh` also fetches that commit of slhdsa-c and compares every vendored file with it.
