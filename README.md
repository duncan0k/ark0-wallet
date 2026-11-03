# ark0-wallet

A wallet for the Ark-0 test network, for Windows, macOS, Linux and Android.

Ark-0 is a test network for trying things out. It may be reset at any time.

## What it does

- **Three kinds of address**, all P2MR outputs (witness version 2) as Ark-0 defines them:
  - the ML-DSA-44 address spends with an ML-DSA-44 signature (FIPS 204; 2,420 bytes);
  - the Schnorr address spends with a BIP-340 signature (64 bytes);
  - the mixed address, once the network's M3 rules are active, has a Schnorr leaf and an ML-DSA-44 leaf.
    After the network's drill tripwire is pulled, only the ML-DSA-44 leaf can spend.
- **pq2 addresses**, for wallets with 24 words, once the network runs its M4 rules (leaf version 0xe2, from
  block 55,000) and six blocks more: an ML-DSA-44 leaf beside an SLH-DSA-SHA2-128s leaf (FIPS 205; 7,856
  bytes), with fresh keys for every address. Payments go through the SLH-DSA leaf unless the ML-DSA-44 leaf
  is chosen, and that is offered only while the node reports ML-DSA-44 checks in these leaves on. If the
  node starts reporting them off before such a payment is broadcast, or refuses it, or drops it, the wallet
  rebuilds it through the SLH-DSA leaf for review; a rebuild always spends the first coin of the payment it
  replaces, and is made only while that coin is free. Through SLH-DSA a payment takes only the coins it
  needs; through ML-DSA-44 it takes every coin of the address. Each address is shown once; at most 20 shown
  and unpaid at a time. A restored wallet checks its pq2 addresses first by their history on the site (until
  20 in a row were never paid, on each chain), and can check further. Addresses it holds in reserve are
  checked on every refresh from six blocks below their last check; Ark-0 has one block producer, so a
  reorganisation deeper than six blocks is not watched for. Two copies of one wallet in use at the
  same time may each show the same pq2 address, which ties the payments to it together; each copy still sees
  every payment to the addresses it showed or holds in reserve, and a further check finds the rest.
- **Keys stay on the device.** They come from 24 recovery words, and the wallet file is encrypted with a
  password (Argon2id, AES-256-GCM). Signing happens in the Rust core, not in the web view.
- **Two confirmations for every payment.** A payment is reviewed in the window, then confirmed in a dialog of
  the operating system, which the page cannot answer. Removing a wallet without its password asks the same way.
- **No payment is made twice without warning.** Every payment is recorded before it is sent. If a payment's
  outcome is unclear, sending again from the same address spends one of its coins, so at most one of the two
  can confirm. The review warns when an earlier payment may have gone out after all, or when coins are being
  spent by a payment this device has no record of.
- **A drill page** shows the state of the network's tripwire and lets you check a transfer from the mixed
  address against the node without broadcasting it.

The interface is in Simplified Chinese, Traditional Chinese, English, Japanese, Korean, Russian and Spanish.

## Where its view of the chain comes from

The wallet asks two independently hosted copies of the same API, on different machines with different nodes:
`https://wallet.ark0.si` and `https://wallet2.ark0.si`.

- Spendable coins are those both list; coins being spent are those either lists. A payment is sent to both.
  When only one answers, or the two disagree, the review and the system dialog say so.
- A payment counts as settled only when six confirmations are proven by the network's block signatures. From
  height 20000 every Ark-0 block carries an ML-DSA-44 signature by a fixed key, which the wallet pins
  (SHA-256 of the key: `eee8548f51f25492de3ae430b7ce7ec549edfaa663b8f577f026ce0498fdd6ad`). The wallet checks
  the headers, the merkle branches and the signatures itself.
- The deployment heights of the network's rules are pinned too. An API that reports others is not describing
  Ark-0, and the wallet does not use it.

What the wallet cannot check by itself: whether both APIs hide the same coin or transaction, or hold a
transaction back. Both are run by the network's operators.

## Releases

Desktop builds are not code-signed. Android release APKs are signed with the certificate whose SHA-256 is
`d849cf62533956e0e682ac0047a55eca9c8f5e8d885320ff78f87829842f644f`; compare it with
`apksigner verify --print-certs` before installing.

## Building

Requirements: Rust (the version in `rust-toolchain.toml`), Node 24 and npm; for Linux the WebKitGTK 4.1
development packages; for Android the SDK and NDK.

```sh
npm ci
npm run build:ui
(cd src-tauri && cargo test --locked)
npx tauri build                                   # desktop
npx tauri android build --apk --target aarch64    # Android
```

`scripts/check-vendor.sh` downloads the mldsa-native release that `src-tauri/csrc/mldsa-native` vendors,
checks its SHA-256 and compares every vendored file with it, and does the same for slhdsa-c at the commit
`src-tauri/csrc/slhdsa-c` vendors. `node scripts/e2e.mjs` runs the end-to-end test
against a running build (see the comment at its top).

## Layout

- `src-tauri/`: the Rust core: keys and signing (ML-DSA-44 from the vendored mldsa-native v2.0.0,
  SLH-DSA-SHA2-128s from the vendored slhdsa-c at a0fc1ff2, BIP-340 from libsecp256k1), the encrypted wallet file, payment records, the two API clients, and the proof checks.
- `ui/`: the interface (Preact).
- `tools/derivation/`: an independent implementation of the key derivation, which produces the test vectors.
- `tools/vectors/`: the pq2 vectors made with p2mr-ts, and its check of spends the core signed
  (`node tools/vectors/run.mjs --pq2 <p2mr-ts checkout>`).

## License

MIT, see `LICENSE`. Vendored code keeps its own license (`src-tauri/csrc/mldsa-native/LICENSE`,
`src-tauri/csrc/slhdsa-c/LICENSE`).
