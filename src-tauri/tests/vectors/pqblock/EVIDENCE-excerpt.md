## `m2_block_20000.hex`: the first block under M2

Block 20000, the first from which Ark-0 requires an ML-DSA-44 block signature
(`../NETWORK.md`, "Rule change at height 20000 (M2)"), as
`bitcoin-cli getblock <hash> 0` returned it, the same bytes on each of the four
nodes the operator runs. Its only transaction is the coinbase. In the coinbase
output that holds the witness commitment, the commitment is followed by one
2425-byte push, `PQB1`, version `01` and the 2420-byte signature, and then by
the signet solution.

| Field | Value |
|---|---|
| Block hash | `000001153177f182a96b4ad6903ed9279cef82b0cfd340f85b55d1ac81ccc1d4` |
| Parent | `000000841874616836f0908d4e6bb2ef8cd55ea0b9323e7084f857d69b2abdb1` (height 19999) |
| Merkle root | `a033e6e2e90b6a833504682382fde920173850a13d3e5f1b981f54a7b8e373ef`, the coinbase's txid |
| Time / nonce | 1791693688 (2026-10-11 04:41:28 UTC) / 2278195 |
| Size | 2772 bytes, one transaction |

Each of the operator's four nodes accepted it, and nodes A and B logged
`BlockChecked: block hash=000001153177f182a96b4ad6903ed9279cef82b0cfd340f85b55d1ac81ccc1d4 state=Valid`.
Its signature also verifies under the key in `../../patches-m2/` 53 with the
ML-DSA-44 code of the patched tree's functional test framework
(`verify_signet_pq_signature` in `test_framework/signet_pq.py`).

## `m2_badblock_*.hex`: the five blocks refused under M2

Five complete blocks at height 20095, above the height 20000 from which Ark-0
requires an ML-DSA-44 block signature (`../NETWORK.md`, "Rule change at height
20000 (M2)"), all built on
`00000107c067fe63e95dab9c05783e221b8be0024a7c79059c9811bd7a40695f` (height
20094) on 2026-10-11. Each has valid proof
of work and a valid classical signet solution, made with the challenge key as
the block producer makes it. In the coinbase output that holds the witness
commitment, each has the push below after the commitment, in place of a valid
ML-DSA-44 block signature, which is the only thing wrong with it. The other
key's seed is the SHA256 of the public string `ark0 m2 negative blocks at
20000: another ML-DSA-44 key, public, test only`, so it controls nothing.

| File | Block hash | The push after the witness commitment |
|---|---|---|
| `m2_badblock_nopush.hex` | `00000001283c2155356bf9afdb2886941e35ff4433d6d5b42fa484bcba44f3b1` | absent: the signet solution follows the commitment directly |
| `m2_badblock_flipped.hex` | `0000007f9ed4affe71837767c9172689b674562e0c9395c53e0dc62290db1e31` | the block's valid push, with bit 0 of its byte 100 (counting from 0; byte 95 of the signature) flipped |
| `m2_badblock_otherkey.hex` | `0000011cb625f3b9fc44c6d93a7eeb911669fbe71e47c12b6260e544ccec9a60` | a valid signature of the block by the other key |
| `m2_badblock_trailing.hex` | `000000fbb48c81097e88ed87183c466f68207966ce7b91a4dcc91141a7d59811` | the block's valid push, followed by `OP_0` |
| `m2_badblock_nonpush.hex` | `00000054caad64dc405a3c084faa341d1b847af0a9adbf3a0737bc20b421cc59` | `OP_1NEGATE` in place of the push |

The same test framework code bears out the three descriptions that involve a
signature: the one in `m2_badblock_flipped.hex` verifies under Ark-0's key
once that bit is flipped back; the one in `m2_badblock_otherkey.hex` verifies
under the other key and not under Ark-0's; and the push in
`m2_badblock_trailing.hex` verifies as it stands: the signature does not cover
what follows it, so that block fails only for the `OP_0`.

On 2026-10-11 each of the operator's four nodes was given each block with
`submitblock` and answered `bad-signet-pqblk`: nodes A and B at 07:20:54 UTC,
the public node and the relay between 07:20:57 and 07:21:56. None of them kept
