#!/usr/bin/env bash
# Re-downloads the mldsa-native v2.0.0 release tarball, checks its SHA-256 against the one recorded in
# src-tauri/csrc/README.md, and compares every vendored file with the tarball's copy. Then fetches slhdsa-c
# at the commit csrc/README.md names and compares every file of csrc/slhdsa-c with that commit's.
#   bash scripts/check-vendor.sh
set -euo pipefail
url=https://github.com/pq-code-package/mldsa-native/archive/refs/tags/v2.0.0.tar.gz
want=97a7305c32b62cbcae97891823176e18ca96d9eaafc3728587d75bb113862a40
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
curl -fsSL -o "$tmp/m.tgz" "$url"
echo "$want  $tmp/m.tgz" | sha256sum -c -
tar -xzf "$tmp/m.tgz" -C "$tmp"
up="$(find "$tmp" -maxdepth 1 -type d -name 'mldsa-native-*')"
vend="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/src-tauri/csrc/mldsa-native"
n=0
while IFS= read -r -d '' f; do
    rel="${f#"$vend"/}"
    if [ "$rel" = LICENSE ]; then src="$up/LICENSE"; else src="$up/mldsa/$rel"; fi
    cmp -s "$f" "$src" || { echo "differs from the release: $rel" >&2; exit 1; }
    n=$((n + 1))
done < <(find "$vend" -type f -print0)
echo "check-vendor: all $n vendored files are identical to mldsa-native v2.0.0"

slh_commit=a0fc1ff253930060d0246aebca06c2538eb92b88
slh_vend="$(dirname "$vend")/slhdsa-c"
git init -q "$tmp/slh"
git -C "$tmp/slh" fetch -q --depth 1 https://github.com/pq-code-package/slhdsa-c.git "$slh_commit"
git -C "$tmp/slh" checkout -q FETCH_HEAD
[ "$(git -C "$tmp/slh" rev-parse HEAD)" = "$slh_commit" ] || { echo "slhdsa-c: not commit $slh_commit" >&2; exit 1; }
m=0
while IFS= read -r -d '' f; do
    rel="${f#"$slh_vend"/}"
    cmp -s "$f" "$tmp/slh/$rel" || { echo "differs from slhdsa-c $slh_commit: $rel" >&2; exit 1; }
    m=$((m + 1))
done < <(find "$slh_vend" -type f -print0)
echo "check-vendor: all $m vendored files are identical to slhdsa-c $slh_commit"
