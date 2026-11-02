#!/usr/bin/env bash
# Builds slhdsa-c the way build.rs does, in the macro environment of other compilers, and runs the
# known-answer test (src-tauri/csrc/test/slh_kat.c, answers from an independent implementation):
#   1. without the byte-order header, with the byte-order macros removed as MSVC has none: the
#      big-endian branch is taken on a little-endian machine, and the known answers must NOT match;
#   2. with the header, emulating MSVC on x64: they must match;
#   3. with the header and the compiler's own macros: they must match;
#   4. with the header, no macros and no MSVC: the build must stop;
#   5. with the header and a target byte order that disagrees with the compiler's: the build must stop.
#   bash scripts/check-byte-order.sh        (needs a C compiler as cc, on a little-endian machine)
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
csrc="$here/src-tauri/csrc"
out="$here/src-tauri/target/byte-order-check"
mkdir -p "$out"
src=("$csrc/pqw_slhdsa128s.c" "$csrc/slhdsa-c/slh_dsa.c" "$csrc/slhdsa-c/slh_sha2.c" "$csrc/slhdsa-c/sha2_256.c" "$csrc/slhdsa-c/sha2_512.c" "$csrc/test/slh_kat.c")
nomacros=(-U__BYTE_ORDER__ -U__ORDER_LITTLE_ENDIAN__ -U__ORDER_BIG_ENDIAN__ -Wno-builtin-macro-redefined)
msvc=(-D_MSC_VER=1940 -D_M_X64=100 -D__forceinline=__inline)
header=(-include "$csrc/pqw_slh_byteorder.h")
build() { cc -O2 -w -I "$csrc" -I "$csrc/slhdsa-c" "$@" "${src[@]}" -o "$out/kat" 2>"$out/build.log"; }
fail=0
expect() { if [ "$1" = "$2" ]; then echo "ok: $3"; else echo "FAILED: $3" >&2; fail=1; fi; }

build "${nomacros[@]}" && { "$out/kat" >/dev/null; r=$?; } || r=build
expect "$r" 1 "1. no header, no byte-order macros: the known answers do not match (the bug)"
build "${nomacros[@]}" "${msvc[@]}" "${header[@]}" -DPQW_TARGET_LITTLE_ENDIAN && { "$out/kat" >/dev/null; r=$?; } || r=build
expect "$r" 0 "2. header, MSVC on x64: the known answers match"
build "${header[@]}" -DPQW_TARGET_LITTLE_ENDIAN && { "$out/kat" >/dev/null; r=$?; } || r=build
expect "$r" 0 "3. header, the compiler's own macros: the known answers match"
build "${nomacros[@]}" "${header[@]}" -DPQW_TARGET_LITTLE_ENDIAN && r=built || r=build
expect "$r" build "4. header, no macros and no MSVC: the build stops"
build "${header[@]}" -DPQW_TARGET_BIG_ENDIAN && r=built || r=build
expect "$r" build "5. header, target big-endian on a little-endian compiler: the build stops"
exit $fail
