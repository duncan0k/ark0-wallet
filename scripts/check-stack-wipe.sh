#!/usr/bin/env bash
# Builds the slhdsa-c wrapper as build.rs does, with gcc and clang at -O0 and -O2, and checks that no copy
# of SK.seed or SK.prf is left on the stack after key generation or signing (src-tauri/csrc/test/slh_stack.c).
#   bash scripts/check-stack-wipe.sh
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
csrc="$here/src-tauri/csrc"
out="$here/src-tauri/target/stack-wipe-check"
mkdir -p "$out"
fail=0
for compiler in gcc clang; do
    command -v "$compiler" >/dev/null || { echo "skipped: $compiler not found"; continue; }
    for opt in -O0 -O2; do
        "$compiler" "$opt" -w -include "$csrc/pqw_slh_byteorder.h" -DPQW_TARGET_LITTLE_ENDIAN -I "$csrc" -I "$csrc/slhdsa-c" \
            "$csrc/pqw_slhdsa128s.c" "$csrc/slhdsa-c/slh_dsa.c" "$csrc/slhdsa-c/slh_sha2.c" "$csrc/slhdsa-c/sha2_256.c" \
            "$csrc/slhdsa-c/sha2_512.c" "$csrc/test/slh_stack.c" -o "$out/probe" || { echo "FAILED to build: $compiler $opt" >&2; fail=1; continue; }
        if "$out/probe" > "$out/result.txt"; then echo "ok: $compiler $opt"; else echo "FAILED: $compiler $opt" >&2; cat "$out/result.txt" >&2; fail=1; fi
    done
done
exit $fail
