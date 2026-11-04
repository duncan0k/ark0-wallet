// The core's commands (src-tauri/src/app.rs), typed. A failed command rejects with { code }.
import { invoke } from '@tauri-apps/api/core';

export type Kind = 'schnorr' | 'mldsa44' | 'mixed' | 'pq2';
export type Path = 'schnorr' | 'mldsa44' | 'slhdsa128s';
/** The three addresses with one output each; pq2 has one per index. */
export type FixedKind = Exclude<Kind, 'pq2'>;

export interface Status { exists: boolean; unlocked: boolean; legacy: boolean | null }

export interface Chain {
  tip: number;
  tip_time: number | null;
  mldsa44_height: number | null;
  mldsa44_allowed: boolean;
  tripwire_height: number | null;
  tripwire_tip: number | null;
  ec_disabled: boolean | null;
  tripwires: { outpoint: string; unspent: boolean }[];
  mixed_allowed: boolean;
  /** H4T, when the node reports the M4 rules at Ark-0's heights. */
  lattice_height: number | null;
  lattice_tip: number | null;
  /** The node reports ML-DSA-44 checks in pq2 (0xe2) leaves off from the next block; null when unknown. */
  mldsa_disabled: boolean | null;
  lattice_tripwires: { outpoint: string; unspent: boolean; key_sha256: string | null; label: string | null }[];
  pq2_allowed: boolean;
}

export type Pq2Status = 'protected' | 'pending' | 'unprotected';
export type Pq2Blocked = 'legacy' | 'waiting' | 'unknown_state' | 'scan_needed' | 'gap_limit';

export interface Pq2Coin { txid: string; vout: number; sats: number; height: number | null; status: Pq2Status; spending: boolean }
export interface Pq2Address { chain: number; index: number; address: string; mldsa44_fits: boolean; spendable: number; pending: number; incoming: number; coins: Pq2Coin[]; complete: boolean }
export interface Pq2View {
  blocked: Pq2Blocked | null;
  allowed: boolean;
  /** pq2 coins may be spent (through SLH-DSA, without change, while the lattice state is unknown). */
  spend_allowed: boolean;
  opens_at: number;
  mldsa44_allowed: boolean;
  mldsa_disabled: boolean | null;
  addresses: Pq2Address[];
  spendable: number;
  pending: number;
  incoming: number;
  complete: boolean;
  change_blocked: boolean;
  scanned: [number, number];
  issued: [number, number];
}

export interface Pq2PlanView {
  address: string;
  mldsa44_allowed: boolean;
  mldsa44_reason: 'disabled' | 'unknown' | 'too_many_coins' | null;
  witness_bytes: number;
  several_coins: boolean;
  staying_coins: number;
  staying_sats: number;
  change_address: string | null;
  change_blocked: boolean;
  /** The txid of the payment this one rebuilds ('' when that one was never sent). */
  rebuilt_from: string | null;
}

export interface AccountView {
  kind: FixedKind;
  address: string;
  shown: boolean;
  path: Path | null;
  spendable: number;
  pending: number;
  incoming: number;
  coins: number;
  complete: boolean;
}

export interface Overview { chain: Chain | null; problem: string | null; accounts: AccountView[]; pq2: Pq2View | null; fetched: number }

export interface SendPlan {
  id: string;
  from: Kind;
  signature: Path;
  to: string;
  send: number;
  fee: number;
  change: number;
  inputs: number;
  vsize: number;
  size: number;
  fee_rate: number;
  left: number;
  truncated: boolean;
  to_self: boolean;
  replaces: number;
  went_out: boolean;
  unclear_elsewhere: boolean;
  unrecorded: boolean;
  one_source: boolean;
  sources_disagree: boolean;
  pq2: Pq2PlanView | null;
}

export type BroadcastResult =
  | { kind: 'sent'; txid: string }
  | { kind: 'rejected'; reason: string }
  | { kind: 'failed'; error: string }
  | { kind: 'unknown' };

/** rebuild_error: the SLH-DSA rebuild of a refused ML-DSA-44 payment was due but could not be planned now (its error code). */
export interface SendResult { result: BroadcastResult; txid: string; sign_ms: number; rebuilt: SendPlan | null; rebuild_error: string | null }

export interface Sent {
  txid: string;
  created: number;
  from: Kind;
  to: string;
  send: number;
  fee: number;
  change: number;
  vsize: number;
  size: number;
  signature: Path;
  inputs: number;
  sign_ms: number;
  status: 'submitting' | 'mempool' | 'confirmed' | 'unknown' | 'rejected' | 'failed' | 'replaced';
  confirmations: number;
  proof_verified: boolean;
  /** An earlier answer about this payment was unclear (or its confirmation is not yet verified). */
  doubted: boolean;
  reason: string;
  /** The pq2 address a pq2 payment spent from. */
  address?: string;
  /** A pq2 payment through the ML-DSA-44 leaf that did not go through and can be rebuilt now. */
  rebuild: boolean;
}

export type CheckResult =
  | { kind: 'allowed'; vsize: number; fee: number }
  | { kind: 'rejected'; reason: string }
  | { kind: 'failed'; error: string };

export interface DrillResult { verdict: CheckResult; signature: Path; vsize: number; size: number; sign_ms: number }

export interface InputCost { kind: Kind; signature: Path; signature_bytes: number; tx_vsize: number; tx_size: number }
export interface AppInfo { version: string; api: string; explorer: string; faucet: string; target: string; fee_rate: number; costs: InputCost[] }

export interface Settings { language: 'auto' | 'zh-Hans' | 'zh-Hant' | 'en' | 'ja' | 'ko' | 'ru' | 'es'; auto_lock_minutes: number }

export interface SelftestReport {
  ok: boolean;
  version: string;
  target: string;
  checks: { name: string; ok: boolean; detail: string }[];
  timings: { name: string; median_ms: number; runs: number }[];
}

export const core = {
  appInfo: () => invoke<AppInfo>('app_info'),
  status: () => invoke<Status>('wallet_status'),
  newPhrase: () => invoke<string[]>('new_phrase'),
  cancelNewWallet: () => invoke<void>('cancel_new_wallet'),
  confirmPhrase: (positions: number[], words: string[]) => invoke<void>('confirm_phrase', { positions, words }),
  createWallet: (password: string) => invoke<Status>('create_wallet', { password }),
  checkRecovery: (text: string) => invoke<{ legacy: boolean }>('check_recovery', { text }),
  restoreWallet: (text: string, password: string) => invoke<Status>('restore_wallet', { text, password }),
  words: () => invoke<string[]>('bip39_words'),
  unlock: (password: string) => invoke<Status>('unlock', { password }),
  lock: () => invoke<void>('lock'),
  touch: () => invoke<void>('touch'),
  revealRecovery: (password: string, locale: string) => invoke<string>('reveal_recovery', { password, locale }),
  changePassword: (old: string, next: string, locale: string) => invoke<void>('change_password', { old, new: next, locale }),
  deleteWallet: (password: string, locale: string) => invoke<Status>('delete_wallet', { password, locale }),
  // The core asks the user in a system dialog first, in this language when the setting follows the system.
  forgetWallet: (locale: string) => invoke<Status>('forget_wallet', { locale }),
  overview: () => invoke<Overview>('overview'),
  planSend: (from: Kind, to: string, amount: string, address?: string, path?: Path) =>
    invoke<SendPlan>('plan_send', { from, to, amount, address: address ?? null, path: path ?? null }),
  pq2NewAddress: () => invoke<{ address: string; index: number }>('pq2_new_address'),
  pq2Scan: (wider: boolean) => invoke<{ found: number; scanned: [number, number]; issued: [number, number] }>('pq2_scan', { wider }),
  planRebuild: (txid: string) => invoke<SendPlan>('plan_rebuild', { txid }),
  confirmSend: (id: string, locale: string) => invoke<SendResult>('confirm_send', { id, locale }),
  activity: () => invoke<Sent[]>('activity'),
  drillCheck: (path: Path, locale: string) => invoke<DrillResult>('drill_check', { path, locale }),
  settingsGet: () => invoke<Settings>('settings_get'),
  settingsSet: (settings: Settings) => invoke<Settings>('settings_set', { settings }),
  qrSvg: (text: string) => invoke<string>('qr_svg', { text }),
  openPage: (page: 'faucet' | 'explorer' | 'tx' | 'address', value?: string) => invoke<void>('open_page', { page, value }),
  selftest: () => invoke<SelftestReport>('selftest'),
};

/** The code of a failed command. */
export function codeOf(err: unknown): string {
  if (typeof err === 'object' && err !== null && typeof (err as { code?: unknown }).code === 'string') return (err as { code: string }).code;
  return 'internal';
}
