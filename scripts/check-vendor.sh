#!/usr/bin/env bash
# Re-downloads the mldsa-native v2.0.0 release tarball, checks its SHA-256 against the one recorded in
# src-tauri/csrc/README.md, and compares every vendored file with the tarball's copy.
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
