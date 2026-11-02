// pq2 test vectors made by the reference, p2mr-ts (its pq2 module), and the reverse check: a pq2 spend the
// Rust core signed, verified by p2mr-ts. Run it with a p2mr-ts checkout that has pq2 (with its
// node_modules installed):
//
//   node tools/vectors/run.mjs --pq2 <path to p2mr-ts>
//
// It writes src-tauri/tests/vectors/pq2.json (the Rust tests check every byte of it), then checks with
// p2mr-ts alone:
// - src-tauri/tests/vectors/pq2-rust.json, a spend the Rust core signed with fresh randomness through each
//   leaf (`PQW_WRITE_PQ2_VECTOR=1 cargo test pq2_rust_spend` writes a new one): its signature messages, its
//   signatures and its witnesses;
// - every pq2 row of src-tauri/tests/vectors/derivation.json (tools/derivation/derive.py): the public keys
//   and the address from the two keygen seeds.
//
// Signatures here are deterministic (SLH-DSA with opt_rand = PK.seed, ML-DSA-44 with rnd = 0), except one
// hedged SLH-DSA spend with a fixed opt_rand, so that every byte is pinned.
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const vectorsDir = join(here, '../../src-tauri/tests/vectors');
const p2mrDir = resolve(process.argv[2] ?? '');
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const p: any = await import(pathToFileURL(join(p2mrDir, 'src/index.ts')).href);

const hex = (b: Uint8Array): string => Buffer.from(b).toString('hex');
const bytes = (h: string): Uint8Array => Uint8Array.from(Buffer.from(h, 'hex'));
const sha = (b: Uint8Array): string => createHash('sha256').update(b).digest('hex');
const H4T = 55000;
const SEQUENCE = 0xfffffffd;

interface Keys {
  readonly name: string;
  readonly mldsa44Seed: Uint8Array;
  readonly slhdsa128sSeed: Uint8Array;
  readonly mldsa44: { publicKey: Uint8Array; secretKey: Uint8Array };
  readonly slhdsa128s: { publicKey: Uint8Array; secretKey: Uint8Array };
}

function keysOf(name: string): Keys {
  const mldsa44Seed = Uint8Array.from(createHash('sha256').update(`ark0-wallet pq2 vectors ${name} mldsa44`).digest());
  const slhdsa128sSeed = Uint8Array.from(
    Buffer.concat([createHash('sha256').update(`ark0-wallet pq2 vectors ${name} slhdsa128s`).digest(), Buffer.alloc(16, name.charCodeAt(0))]),
  );
  return {
    name,
    mldsa44Seed,
    slhdsa128sSeed,
    mldsa44: p.mldsa44Keygen(mldsa44Seed),
    slhdsa128s: p.slhdsa128sKeygen(slhdsa128sSeed),
  };
}

const pq2Keys = (k: Keys) => ({ mldsa44PublicKey: k.mldsa44.publicKey, slhdsa128sPublicKey: k.slhdsa128s.publicKey });
const chain = { activationHeight: H4T, tipHeight: H4T + 6 };

function outputView(k: Keys) {
  const out = p.createPq2Output({ ...pq2Keys(k), network: 'signet', chain });
  const leaf = (l: { script: Uint8Array; leafHash: Uint8Array; controlBlock: Uint8Array }) => ({
    script_len: l.script.length,
    script_sha256: sha(l.script),
    leaf_hash: hex(l.leafHash),
    control_block: hex(l.controlBlock),
  });
  return {
    keys: k.name,
    root: hex(out.merkleRoot),
    script_pubkey: hex(out.scriptPubKey),
    address: out.address,
    mldsa44_leaf: leaf(out.mldsa44Leaf),
    slhdsa128s_leaf: { ...leaf(out.slhdsa128sLeaf), script: hex(out.slhdsa128sLeaf.script) },
  };
}

interface SpendSpec {
  readonly description: string;
  readonly leaf: 'mldsa44' | 'slhdsa128s';
  readonly from: Keys;
  readonly coins: readonly { txid: string; vout: number; sats: number }[];
  readonly outputs: readonly { sats: number; scriptPubKey: Uint8Array }[];
  readonly optRand?: Uint8Array;
}

function spend(spec: SpendSpec) {
  const from = p.createPq2Output({ ...pq2Keys(spec.from), network: 'signet', chain });
  const tx = {
    version: 2,
    locktime: H4T,
    // txids as shown are reversed in the serialization
    inputs: spec.coins.map((c) => ({ txid: bytes(c.txid).reverse(), vout: c.vout, sequence: SEQUENCE, witness: [] as Uint8Array[] })),
    outputs: spec.outputs.map((o) => ({ amount: BigInt(o.sats), scriptPubKey: o.scriptPubKey })),
  };
  const spentOutputs = spec.coins.map((c) => ({ amount: BigInt(c.sats), scriptPubKey: from.scriptPubKey }));
  const unsigned = p.encodeTransaction(tx, { witness: false });
  const sighashes: string[] = [];
  const witnesses = spec.coins.map((_, inputIndex) => {
    const params = { ...pq2Keys(spec.from), leaf: spec.leaf, tx, inputIndex, spentOutputs };
    sighashes.push(hex(p.pq2Sighash(params)));
    const signature = p.signPq2Input({
      ...params,
      secretKey: spec.leaf === 'mldsa44' ? spec.from.mldsa44.secretKey : spec.from.slhdsa128s.secretKey,
      extraEntropy: spec.optRand ?? false,
    });
    return p.assemblePq2Witness({ ...pq2Keys(spec.from), leaf: spec.leaf, signature });
  });
  const signedTx = { ...tx, inputs: tx.inputs.map((input, i) => ({ ...input, witness: witnesses[i] })) };
  const signed = p.encodeTransaction(signedTx);
  const base = unsigned.length;
  const weight = base * 3 + signed.length;
  return {
    description: spec.description,
    keys: spec.from.name,
    leaf: spec.leaf,
    variant: spec.optRand ? 'hedged' : 'deterministic',
    ...(spec.optRand ? { opt_rand: hex(spec.optRand) } : {}),
    lock_time: H4T,
    inputs: spec.coins,
    outputs: spec.outputs.map((o) => ({ sats: o.sats, script_pubkey: hex(o.scriptPubKey) })),
    unsigned_hex: hex(unsigned),
    sighashes,
    witness_sizes: witnesses.map((w: Uint8Array[]) => {
      // the serialized size of one input's witness: item count, then each item with its length
      const compact = (n: number) => (n < 0xfd ? 1 : 3);
      return compact(w.length) + w.reduce((s, item) => s + compact(item.length) + item.length, 0);
    }),
    signed_hex: hex(signed),
    txid: hex(p.computeTxid(signedTx).slice().reverse()),
    wtxid: hex(p.computeWtxid(signedTx).slice().reverse()),
    size: signed.length,
    base_size: base,
    weight,
    vsize: Math.ceil(weight / 4),
  };
}

function generate(): void {
  const b = keysOf('B');
  const c = keysOf('C');
  const cOut = p.createPq2Output({ ...pq2Keys(c), network: 'signet', chain });
  const elsewhere = p.createPq2Output({ ...pq2Keys(keysOf('D')), network: 'signet', chain });
  const coins = [
    { txid: '11'.repeat(32), vout: 0, sats: 150_000 },
    { txid: '22'.repeat(32), vout: 3, sats: 60_000 },
  ];
  const outputs = [
    { sats: 100_000, scriptPubKey: elsewhere.scriptPubKey },
    { sats: 50_000, scriptPubKey: cOut.scriptPubKey },
  ];
  const json = {
    _note: 'Made by tools/vectors/pq2.ts from p2mr-ts (pq2.ts). The Rust tests check every byte against it.',
    generator: 'tools/vectors/pq2.ts',
    constants: { h4t: H4T, sequence: SEQUENCE, leaf_version: 'e2', control_byte: 'e3' },
    keys: [b, c].map((k) => ({
      name: k.name,
      mldsa44_seed: hex(k.mldsa44Seed),
      slhdsa128s_seed: hex(k.slhdsa128sSeed),
      mldsa44_public_key_sha256: sha(k.mldsa44.publicKey),
      slhdsa128s_public_key: hex(k.slhdsa128s.publicKey),
    })),
    outputs: [outputView(b), outputView(c)],
    spends: [
      spend({ description: 'two coins of output B through leaf B (SLH-DSA), change to output C', leaf: 'slhdsa128s', from: b, coins, outputs }),
      spend({ description: 'the same through leaf A (ML-DSA-44)', leaf: 'mldsa44', from: b, coins, outputs }),
      spend({
        description: 'one coin of output B through leaf B, hedged with a fixed opt_rand, no change',
        leaf: 'slhdsa128s',
        from: b,
        coins: coins.slice(0, 1),
        outputs: [{ sats: 130_000, scriptPubKey: elsewhere.scriptPubKey }],
        optRand: bytes('0138213bcc35b2b9267e084fae3b1594'),
      }),
    ],
  };
  const text = JSON.stringify(json, null, 1) + '\n';
  writeFileSync(join(vectorsDir, 'pq2.json'), text);
  console.log(`pq2.json: ${json.spends.length} spends, sha256 ${sha(Buffer.from(text))}`);
}

function check(ok: boolean, what: string): void {
  if (!ok) {
    console.error(`MISMATCH: ${what}`);
    process.exitCode = 1;
  }
}

/** The Rust core's own spends, verified by p2mr-ts. */
function verifyRust(): void {
  const v = JSON.parse(readFileSync(join(vectorsDir, 'pq2-rust.json'), 'utf8'));
  let n = 0;
  for (const s of v.spends) {
    const keys = { mldsa44PublicKey: bytes(s.mldsa44_public_key), slhdsa128sPublicKey: bytes(s.slhdsa128s_public_key) };
    const out = p.createPq2Output({ ...keys, network: 'signet', chain });
    check(out.address === s.address, `${s.description}: address`);
    const tx = p.decodeTransaction(bytes(s.signed_hex));
    check(tx.locktime === H4T && tx.inputs.every((i: { sequence: number }) => i.sequence === SEQUENCE), `${s.description}: lock time and sequence`);
    const spentOutputs = s.inputs.map((i: { sats: number }) => ({ amount: BigInt(i.sats), scriptPubKey: out.scriptPubKey }));
    const unsignedTx = { ...tx, inputs: tx.inputs.map((i: object) => ({ ...i, witness: [] })) };
    tx.inputs.forEach((input: { witness: Uint8Array[] }, inputIndex: number) => {
      const message = p.pq2Sighash({ ...keys, leaf: s.leaf, tx: unsignedTx, inputIndex, spentOutputs });
      check(hex(message) === s.sighashes[inputIndex], `${s.description}: sighash ${inputIndex}`);
      const chunks = input.witness.slice(0, -2);
      const signature = s.leaf === 'mldsa44' ? Uint8Array.from(Buffer.concat(chunks)) : p.joinSlhdsa128sSignature(chunks);
      const valid = s.leaf === 'mldsa44'
        ? p.mldsa44Verify(keys.mldsa44PublicKey, message, signature)
        : p.slhdsa128sVerify(keys.slhdsa128sPublicKey, message, signature);
      check(valid, `${s.description}: signature ${inputIndex} verifies`);
      const witness = p.assemblePq2Witness({ ...keys, leaf: s.leaf, signature });
      check(witness.length === input.witness.length && witness.every((w: Uint8Array, i: number) => hex(w) === hex(input.witness[i]!)), `${s.description}: witness ${inputIndex}`);
      n += 1;
    });
    check(hex(p.computeTxid(tx).slice().reverse()) === s.txid, `${s.description}: txid`);
  }
  console.log(`pq2-rust.json: ${n} inputs signed by the Rust core verified by p2mr-ts`);
}

/** derive.py's pq2 rows: keys from the keygen seeds, and the address, by p2mr-ts. */
function verifyDerivation(): void {
  const v = JSON.parse(readFileSync(join(vectorsDir, 'derivation.json'), 'utf8'));
  let n = 0;
  for (const w of v.wallets) {
    for (const r of w.pq2) {
      const ml = p.mldsa44Keygen(bytes(r.mldsa44.keygen_seed));
      const slh = p.slhdsa128sKeygen(bytes(r.slhdsa128s.keygen_seed));
      check(sha(ml.publicKey) === r.mldsa44.public_key_sha256, `derivation ${r.chain}/${r.index}: ML-DSA-44 key`);
      check(hex(slh.publicKey) === r.slhdsa128s.public_key, `derivation ${r.chain}/${r.index}: SLH-DSA key`);
      const out = p.createPq2Output({ mldsa44PublicKey: ml.publicKey, slhdsa128sPublicKey: slh.publicKey, network: 'signet', chain });
      check(out.address === r.address, `derivation ${r.chain}/${r.index}: address`);
      n += 1;
    }
  }
  console.log(`derivation.json: ${n} pq2 rows agree with p2mr-ts`);
}

generate();
verifyRust();
verifyDerivation();
