/*
 * Force-included before every file of slhdsa-c (build.rs: /FI with MSVC, -include otherwise), which is
 * left unmodified. slhdsa-c chooses its byte swaps with `#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__`. A
 * compiler that defines neither macro (MSVC) reads both as 0 and takes the big-endian branch on a
 * little-endian machine: its keys and signatures would then verify only against themselves. So:
 * - a compiler that defines any of the three macros must define all three, consistently;
 * - MSVC on its little-endian targets gets them defined here;
 * - anything else does not build;
 * - and the result must agree with the byte order Cargo found for the target (PQW_TARGET_*_ENDIAN).
 */
#ifndef PQW_SLH_BYTEORDER_H
#define PQW_SLH_BYTEORDER_H

#if defined(__BYTE_ORDER__) || defined(__ORDER_LITTLE_ENDIAN__) || defined(__ORDER_BIG_ENDIAN__)
#if !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || !defined(__ORDER_BIG_ENDIAN__)
#error "the compiler defines only some of __BYTE_ORDER__, __ORDER_LITTLE_ENDIAN__ and __ORDER_BIG_ENDIAN__"
#endif
#if __ORDER_LITTLE_ENDIAN__ == __ORDER_BIG_ENDIAN__
#error "__ORDER_LITTLE_ENDIAN__ and __ORDER_BIG_ENDIAN__ are equal"
#endif
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__ && __BYTE_ORDER__ != __ORDER_BIG_ENDIAN__
#error "__BYTE_ORDER__ is neither __ORDER_LITTLE_ENDIAN__ nor __ORDER_BIG_ENDIAN__"
#endif
#elif defined(_MSC_VER) && (defined(_M_IX86) || defined(_M_X64) || defined(_M_ARM) || defined(_M_ARM64))
/* Every MSVC target is little-endian. */
#define __ORDER_LITTLE_ENDIAN__ 1234
#define __ORDER_BIG_ENDIAN__ 4321
#define __BYTE_ORDER__ __ORDER_LITTLE_ENDIAN__
#else
#error "unknown compiler and target: the byte order cannot be determined"
#endif

#if defined(PQW_TARGET_LITTLE_ENDIAN) && !defined(PQW_TARGET_BIG_ENDIAN)
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "the compiler's byte order disagrees with the target's (little-endian)"
#endif
#elif defined(PQW_TARGET_BIG_ENDIAN) && !defined(PQW_TARGET_LITTLE_ENDIAN)
#if __BYTE_ORDER__ != __ORDER_BIG_ENDIAN__
#error "the compiler's byte order disagrees with the target's (big-endian)"
#endif
#else
#error "the build did not say the target's byte order (PQW_TARGET_LITTLE_ENDIAN or PQW_TARGET_BIG_ENDIAN)"
#endif

#endif /* PQW_SLH_BYTEORDER_H */
