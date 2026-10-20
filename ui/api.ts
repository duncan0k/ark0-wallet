// The core's commands (src-tauri/src/app.rs), typed. A failed command rejects with { code }.
import { invoke } from '@tauri-apps/api/core';

export type Kind = 'schnorr' | 'mldsa44' | 'mixed';
export type Path = 'schnorr' | 'mldsa44';

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
}

export interface AccountView {
  kind: Kind;
  address: string;
  shown: boolean;
  path: Path | null;
  spendable: number;
  pending: number;
  incoming: number;
  coins: number;
  complete: boolean;
}

export interface Overview { chain: Chain | null; problem: string | null; accounts: AccountView[]; fetched: number }

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
}

export type BroadcastResult =
  | { kind: 'sent'; txid: string }
  | { kind: 'rejected'; reason: string }
  | { kind: 'failed'; error: string }
  | { kind: 'unknown' };

export interface SendResult { result: BroadcastResult; txid: string; sign_ms: number }

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
  planSend: (from: Kind, to: string, amount: string) => invoke<SendPlan>('plan_send', { from, to, amount }),
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
