# A private network for the privnet build

The desktop wallet's `privnet` build (`src-tauri/src/net.rs`) reads its network from a file. This directory
makes such a network on one Linux machine and runs the end-to-end checks against it, through the wallet's
command layer:

- three nodes of the `ark0-node-m4tb` release, on a custom signet whose challenge is a 1-of-1 multisig of a key
  the harness holds: `n1` and `n2` with the M4 rules, `n3` without `-signetlatticetripwire` (a source that has
  not upgraded);
- a copy of the site's wallet API (`web/ark0web/wallet.py`) in front of each: A on `n1`, B on `n2`, C on `n3`;
- blocks made by `contrib/signet/miner` of the release's source tree, signed by `n1`'s `signer` wallet.

The heights are small: OP_CHECKMLDSA44 from 120, the 0xe0 tripwire rules from 130, OP_CHECKSLHDSA128S from 140,
H4T (`p2mr_lattice_tripwire`) from 160, so pq2 opens at 166. P2MR is buried at height 1 on every custom signet.
The network has no ML-DSA-44 block signature (`-signetpqblock`): the wallet's file gives it a height above the
test range, so no confirmation here is ever proven by block signatures.

## What it needs

- The release binaries, downloaded and verified as `ark0/JOIN.md` of bitcoin-p2mr-patches (tag
  `ark0-node-m4tb`) says: the signature of `SHA256SUMS` by `025D 989B 68FF 923F 8EF6 9D4B 28F6 5A19 58A2 361A`,
  then `sha256sum -c` before and after unpacking. On Ubuntu 24.04 they need `libevent-extra-2.1-7t64` and
  `libevent-pthreads-2.1-7t64`.
- Bitcoin Core `v31.1` (commit 9be056a) with the release's ten patch series applied in `apply.sh`'s order
  (`git am`, no build): `contrib/signet/miner` and `test/functional/test_framework` (for the key) come from it.
  No patch set changes the miner.
- The site's `web/` directory. It runs with the standard library only.
- The wallet's `src-tauri/`, with Rust (the checks build its tests with `--features privnet`).

## Running it

```bash
export PRIVNET_BIN=/path/to/ark0-node-m4tb/bin PRIVNET_SRC=/path/to/bitcoin PRIVNET_SITE=/path/to/web
export PRIVNET_DIR=/tmp/<a new directory> PRIVNET_WALLET_SRC=/path/to/wallet/src-tauri
python3 privnet.py setup          # about 3 minutes: 111 blocks, the tripwires, the rules, the sites
python3 checks.py all             # the eight checks; answers in $PRIVNET_DIR/evidence/
python3 privnet.py stop
```

`setup` mines 110 blocks with the challenge alone, makes the tripwire outputs in one transaction of the `drill`
wallet (two for M3, three lattice tripwires, the third the drill output), mines it, and restarts the nodes with
the rules. It writes `network.json` (the challenge, its key, the outpoints) and the wallet's two network files:
`wallet-ab.json` (sources A and B) and `wallet-ac.json` (A and the source that has not upgraded).

A wallet step alone:

```bash
cd "$PRIVNET_WALLET_SRC"
ARK0_PRIVNET_CONFIG=$PRIVNET_DIR/wallet-ab.json ARK0_PRIVNET_WALLET_DIR=$PRIVNET_DIR/wallet-created \
ARK0_PRIVNET_STEP=overview ARK0_PRIVNET_OUT=/tmp/<dir>/overview.json \
  cargo test --features privnet --lib -- --exact app::privnet_e2e::privnet_e2e
```

Without `ARK0_PRIVNET_STEP` that test does nothing, so `cargo test --features privnet` passes without a network.
With it, run the one test alone, as above: the network file is read once per process, and the other tests
expect Ark-0's.

The steps (`src-tauri/src/privnet_e2e.rs`): `overview`, `activity`, `scan`, `address` (scanning first when the
wallet needs it), `plan` and `send` (`from`, `to`, `amount`, `path`: `mldsa44` or `slhdsa128s`), and `held` (a
spend that waits, signed, right before it is recorded and sent, until `held-go` appears in
`ARK0_PRIVNET_SIGNAL`; then it goes as the wallet sends it, and the plan the wallet offers after it is confirmed).
A step uses only a wallet directory that is new or empty, or that carries the marker `privnet-network` (the
network's challenge) the harness wrote when it made it; any other directory, a release wallet's above all, is
refused before anything in it is opened. The first step on a data directory makes the wallet as the create flow does, from fixed words (with `restore`
in the arguments, restored from them; with `legacy`, from a web-wallet backup code); later steps unlock it.

## The site's limits

The sites run with the limits of the deployed site, except those it reads from its settings for browsers
(`RATE_*`, `FRESH_STATE_*`, raised here). Two that it does not read apply as on Ark-0, and every step here
comes from one visitor, 127.0.0.1: `/api/utxos` takes 20 lookups from a visitor at once and one a second after
that, and the node's UTXO scans 10 at once and two a second for all visitors. On this network a refresh of the
wallet looks up 7 addresses on each site, a plan 7 and its confirmation 13 more, so `checks.py` waits
`PRIVNET_PACE` seconds (25) before each step and between a plan and its confirmation, as a person would; with
no wait, a confirmation right after a plan is refused (`limit`). A recovery scan cannot be paced from outside:
it makes one lookup per index, and stops at the eleventh.

## Building the app itself

```bash
ARK0_PRIVNET_CONFIG=$PRIVNET_DIR/wallet-ab.json \
  cargo tauri dev --features privnet --config src-tauri/tauri.privnet.conf.json
```

The privnet build refuses to start without its file, with Ark-0's challenge in it, or under the release's app
identifier: it keeps its files under `si.ark0.wallet.privnet`, never a release wallet's.
