// Test vectors for the Rust signing core, made by the reference: the Ark-0 web wallet's own modules
// and the p2mr-ts sources it vendors. tools/vectors/run.mjs bundles this file against a checkout of the
// web wallet and writes src-tauri/tests/vectors/p2mr.json; the Rust tests read that file.
//
// Signatures are made deterministically here (BIP-340 with all-zero auxiliary randomness, ML-DSA-44
// without extra entropy), so a vector pins every byte of a signed transaction.
import { schnorr } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';
import {
  assembleMldsa44Witness,
  assembleScriptPathWitness,
  assembleTripwiredWitness,
  bytesToHex,
  computeTxid,
  computeWtxid,
  encodeTransaction,
  hexToBytes,
  mldsa44Sighash,
  p2mrScriptPathSighash,
  reverseBytes,
  signMldsa44Input,
  TRIPWIRED_LEAF_VERSION,
  tripwiredSighash,
  type SpentOutput,
  type Transaction,
  type TxOutput,
} from 'p2mr-ts';
import { deriveKeys, encodeBackup, type Keys } from 'wallet/keys';
import { parseDestination } from 'wallet/dest';
import {
  mldsa44Account,
  schnorrAccount,
  signatureOf,
  tripwiredAccount,
  unsignedTransaction,
  type Account,
  type Coin,
  type Input,
} from 'wallet/spend';

const hex = bytesToHex;
const sha = (b: Uint8Array): string => hex(sha256(b));
const AUX = new Uint8Array(32);
const M1_HEIGHT = 8600;
const H3 = 30000;
const TIP = 40000;

function seedOf(byte: number): Uint8Array {
  return Uint8Array.from({ length: 32 }, (_, i) => (byte + i) & 0xff);
}

interface Wallet {
  readonly seed: Uint8Array;
  readonly keys: Keys;
  readonly schnorr: Account;
  readonly mldsa44: Account;
  readonly mixedSchnorr: Account;
  readonly mixedMldsa44: Account;
}

function wallet(seed: Uint8Array): Wallet {
  const keys = deriveKeys(seed);
  return {
    seed,
    keys,
    schnorr: schnorrAccount(keys, 'signet'),
    mldsa44: mldsa44Account(keys, 'signet', M1_HEIGHT, TIP),
    mixedSchnorr: tripwiredAccount(keys, 'signet', { tripwireHeight: H3, tipHeight: TIP }, 'schnorr'),
    mixedMldsa44: tripwiredAccount(keys, 'signet', { tripwireHeight: H3, tipHeight: TIP }, 'mldsa44'),
  };
}

function leafView(account: Account): Record<string, unknown> {
  return {
    leaf_script_len: account.leaf.script.length,
    leaf_script_sha256: sha(account.leaf.script),
    leaf_hash: hex(account.leaf.leafHash),
    control_block: hex(account.leaf.controlBlock),
  };
}

function keyVector(w: Wallet): Record<string, unknown> {
  return {
    seed: hex(w.seed),
    backup: encodeBackup(w.seed),
    schnorr_secret: hex(w.keys.schnorrSecret),
    xonly: hex(w.keys.xonly),
    mldsa44_public_key_sha256: sha(w.keys.mldsa44.publicKey),
    mldsa44_secret_key_sha256: sha(w.keys.mldsa44.secretKey),
    schnorr: { address: w.schnorr.address, script_pubkey: hex(w.schnorr.scriptPubKey), leaf_script: hex(w.schnorr.leaf.script), ...leafView(w.schnorr) },
    mldsa44: { address: w.mldsa44.address, script_pubkey: hex(w.mldsa44.scriptPubKey), ...leafView(w.mldsa44) },
    mixed: {
      address: w.mixedSchnorr.address,
      script_pubkey: hex(w.mixedSchnorr.scriptPubKey),
      schnorr_leaf: { leaf_script: hex(w.mixedSchnorr.leaf.script), ...leafView(w.mixedSchnorr) },
      mldsa44_leaf: leafView(w.mixedMldsa44),
    },
  };
}

/** Sign deterministically, the way spend.ts signs but without fresh randomness. */
function signDeterministic(tx: Transaction, inputs: readonly Input[], keys: Keys): { signed: Transaction; sighashes: string[] } {
  const spentOutputs: SpentOutput[] = inputs.map(({ coin, account }) => ({ amount: coin.sats, scriptPubKey: account.scriptPubKey }));
  const sighashes: string[] = [];
  const witnesses = inputs.map(({ account }, inputIndex) => {
    const base = { tx, inputIndex, spentOutputs };
    if (account.tripwired !== undefined) {
      const path = account.tripwired.path;
      const tk = { xonlyPubkey: keys.xonly, publicKey: keys.mldsa44.publicKey };
      const message = tripwiredSighash({ ...tk, ...base, path });
      sighashes.push(hex(message));
      const signature = path === 'schnorr'
        ? schnorr.sign(message, keys.schnorrSecret, AUX)
        : signMldsa44Input({ ...base, leafScript: account.leaf.script, leafVersion: TRIPWIRED_LEAF_VERSION, secretKey: keys.mldsa44.secretKey, extraEntropy: false });
      return assembleTripwiredWitness({ ...tk, path, signature });
    }
    if (account.kind === 'schnorr') {
      const message = p2mrScriptPathSighash({ ...base, leafHash: account.leaf.leafHash });
      sighashes.push(hex(message));
      const signature = schnorr.sign(message, keys.schnorrSecret, AUX);
      return assembleScriptPathWitness({ stack: [signature], leafScript: account.leaf.script, controlBlock: account.leaf.controlBlock });
    }
    const message = mldsa44Sighash({ ...base, leafScript: account.leaf.script });
    sighashes.push(hex(message));
    const signature = signMldsa44Input({ ...base, leafScript: account.leaf.script, secretKey: keys.mldsa44.secretKey, extraEntropy: false });
    return assembleMldsa44Witness({ signature, leafScript: account.leaf.script, controlBlock: account.leaf.controlBlock });
  });
  return { signed: { ...tx, inputs: tx.inputs.map((input, i) => ({ ...input, witness: witnesses[i] as Uint8Array[] })) }, sighashes };
}

function coin(byte: number, vout: number, sats: bigint): Coin {
  return { txid: hex(Uint8Array.from({ length: 32 }, (_, i) => (byte * 7 + i * 13) & 0xff)), vout, sats, height: 31000 };
}

function spendVector(description: string, w: Wallet, inputs: readonly Input[], outputs: readonly TxOutput[], lockTime: number): Record<string, unknown> {
  const tx = unsignedTransaction(inputs, outputs, lockTime);
  const { signed, sighashes } = signDeterministic(tx, inputs, w.keys);
  const size = encodeTransaction(signed).length;
  const base = encodeTransaction(signed, { witness: false }).length;
  return {
    description,
    seed: hex(w.seed),
    lock_time: lockTime,
    inputs: inputs.map(({ coin: c, account }) => ({
      txid: c.txid,
      vout: c.vout,
      sats: Number(c.sats),
      account: account.kind === 'tripwired' ? 'mixed' : account.kind,
      signature: signatureOf(account),
    })),
    outputs: outputs.map((o) => ({ script_pubkey: hex(o.scriptPubKey), sats: Number(o.amount) })),
    unsigned_hex: hex(encodeTransaction(tx, { witness: false })),
    sighashes,
    signed_hex: hex(encodeTransaction(signed)),
    signed_sha256: sha(encodeTransaction(signed)),
    txid: hex(reverseBytes(computeTxid(signed))),
    wtxid: hex(reverseBytes(computeWtxid(signed))),
    size,
    base_size: base,
    weight: base * 3 + size,
    vsize: Math.ceil((base * 3 + size) / 4),
  };
}

const a = wallet(Uint8Array.from({ length: 32 }, (_, i) => i));
const b = wallet(seedOf(0x80));
const out = (account: Account, sats: bigint): TxOutput => ({ amount: sats, scriptPubKey: account.scriptPubKey });
const p2wpkh = hexToBytes('0014751e76e8199196d454941c45d1b3a323f1433bd6');
const p2tr = hexToBytes('5120a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c');

const spends = [
  spendVector('Schnorr address to another wallet, with change', a, [{ coin: coin(1, 0, 100_000n), account: a.schnorr }], [out(b.mldsa44, 40_000n), out(a.schnorr, 59_000n)], H3),
  spendVector('ML-DSA-44 address to a P2WPKH output, no change', a, [{ coin: coin(2, 1, 50_000n), account: a.mldsa44 }], [{ amount: 47_000n, scriptPubKey: p2wpkh }], H3),
  spendVector('Mixed address, one input through each leaf', a, [
    { coin: coin(3, 0, 70_000n), account: a.mixedSchnorr },
    { coin: coin(4, 2, 30_000n), account: a.mixedMldsa44 },
  ], [out(b.mixedSchnorr, 90_000n)], H3),
  spendVector('Three addresses to a P2TR output, change to the ML-DSA-44 address, lock time at M1', b, [
    { coin: coin(5, 3, 20_000n), account: b.schnorr },
    { coin: coin(6, 0, 25_000n), account: b.mldsa44 },
    { coin: coin(7, 1, 40_000n), account: b.mixedMldsa44 },
  ], [{ amount: 60_000n, scriptPubKey: p2tr }, out(b.mldsa44, 15_000n)], M1_HEIGHT),
];

const destinations = [
  a.mldsa44.address,
  a.mixedSchnorr.address.toUpperCase(),
  'tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx',
  'tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy',
  'tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c',
  'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4',
  'tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsy',
  'tb1z' + 'q'.repeat(10),
  'tb1sw50qgdz25j',
  ' ' + b.schnorr.address + '\n',
  '',
].map((text) => {
  const parsed = parseDestination(text, 'tb');
  return typeof parsed === 'string'
    ? { text, result: parsed }
    : { text, result: 'ok', address: parsed.address, script_pubkey: hex(parsed.scriptPubKey), dust: Number(parsed.dust) };
});

console.log(JSON.stringify({
  generator: 'tools/vectors/gen.ts',
  constants: { m1_height: M1_HEIGHT, h3: H3, tip: TIP, schnorr_aux: hex(AUX) },
  keys: [keyVector(a), keyVector(b)],
  spends,
  destinations,
}, null, 2));
