// The overview: what the wallet can spend, its three addresses, its pq2 coins, and the network.
import { useState } from 'preact/hooks';
import type { AccountView, Chain, FixedKind, Kind, Overview as OverviewData, Pq2Status, Pq2View } from '../api';
import { codeOf, core } from '../api';
import { Amount, Button, Card, Chip, CopyButton, Icon, Mono, Notice, useToast } from '../components';
import { errorText, fill, m } from '../i18n';
import { ago, amount, coins, group, shorten } from '../format';

export const ORDER: FixedKind[] = ['mldsa44', 'schnorr', 'mixed'];
export const KIND_ICON: Record<Kind, string> = { mldsa44: 'drill', schnorr: 'lock', mixed: 'leaf', pq2: 'drill' };
export const PQ2_TONE: Record<Pq2Status, 'good' | 'accent' | 'warn'> = { protected: 'good', pending: 'accent', unprotected: 'warn' };

export function statusOf(a: AccountView, chain: Chain | null): { tone: 'good' | 'warn' | 'neutral'; text: string } {
  const s = m().status;
  if (a.shown) {
    if (a.kind === 'mixed') return { tone: 'good', text: a.path === 'mldsa44' ? s.pathMldsa44 : s.pathSchnorr };
    return { tone: 'good', text: s.ready };
  }
  if (a.kind === 'mldsa44') return { tone: 'warn', text: s.waitM1 };
  if (chain && chain.tripwire_height !== null && chain.tip < chain.tripwire_height + 6) return { tone: 'warn', text: s.waitM3 };
  return { tone: 'warn', text: s.waitTripwire };
}

export function Overview({ data, legacy, loading, onRetry, onSend, onReceive }: {
  data: OverviewData | null;
  legacy: boolean;
  loading: boolean;
  onRetry: () => void;
  onSend: () => void;
  onReceive: () => void;
}) {
  const o = m().overview;
  const toast = useToast();
  if (!data) return <div class="page"><div class="skeleton-hero" /><div class="skeleton-card" /></div>;
  if (data.problem) {
    const key = `problem_${data.problem}` as keyof ReturnType<typeof m>['overview'];
    return (
      <div class="page">
        <Notice tone="bad">
          <strong>{o.problemTitle}</strong>
          <p>{(o[key] as string) ?? o.problem_unreachable}</p>
          <div class="notice-actions"><Button size="sm" icon="refresh" busy={loading} onClick={onRetry}>{m().common.retry}</Button></div>
        </Notice>
      </div>
    );
  }
  const shown = data.accounts.filter((a) => a.shown);
  const pq2 = data.pq2;
  const available = shown.reduce((s, a) => s + a.spendable, 0) + (pq2?.spendable ?? 0);
  const incoming = data.accounts.reduce((s, a) => s + a.incoming, 0) + (pq2?.incoming ?? 0);
  const outgoing = data.accounts.reduce((s, a) => s + a.pending, 0) + (pq2?.pending ?? 0);
  const complete = data.accounts.every((a) => a.complete) && (pq2?.complete ?? true);
  const sorted = ORDER.map((k) => data.accounts.find((a) => a.kind === k)).filter((a): a is AccountView => !!a);

  return (
    <div class="page">
      <section class="balance">
        <div class="balance-main">
          <span class="eyebrow">{o.available}</span>
          <Amount sats={available} size="xl" />
          <div class="balance-sub">
            {incoming > 0 && <Chip tone="accent" dot>{fill(o.incoming, { amount: amount(incoming) })}</Chip>}
            {outgoing > 0 && <Chip tone="neutral" dot>{fill(o.outgoing, { amount: amount(outgoing) })}</Chip>}
            {!complete && <Chip tone="warn">{o.incomplete}</Chip>}
          </div>
        </div>
        <div class="balance-actions">
          <Button kind="primary" size="lg" icon="send" onClick={onSend}>{m().nav.send}</Button>
          <Button kind="secondary" size="lg" icon="receive" onClick={onReceive}>{m().nav.receive}</Button>
          <Button kind="ghost" size="lg" icon="drop" onClick={() => openFaucet(data.accounts.find((a) => a.kind === 'mldsa44' && a.shown)?.address, toast)}>{m().common.faucet}</Button>
        </div>
      </section>

      {legacy && <LegacyNotice />}
      {available === 0 && incoming === 0 && <Notice tone="info">{o.noCoinsYet}</Notice>}

      <section class="card accounts">
        <header class="card-head"><h3>{o.addresses}</h3></header>
        <ul class="account-list">
          {sorted.map((a) => <AccountRow account={a} chain={data.chain} />)}
        </ul>
      </section>

      {pq2 && <Pq2Card pq2={pq2} onScanned={onRetry} />}

      {data.chain && <NetworkCard chain={data.chain} fetched={data.fetched} />}
    </div>
  );
}

/** Why no new pq2 address can be shown now, in words. */
export function pq2Blocked(pq2: Pq2View): string | null {
  const p = m().pq2;
  switch (pq2.blocked) {
    case null: return null;
    case 'waiting': return fill(p.blocked_waiting, { n: group(pq2.opens_at) });
    default: return p[`blocked_${pq2.blocked}`];
  }
}

/**
 * pq2: its coins with their status, why no new address can be shown when none can, and the recovery check
 * of a restored wallet, with the wider check for coins beyond the range it covered.
 */
function Pq2Card({ pq2, onScanned }: { pq2: Pq2View; onScanned: () => void }) {
  const p = m().pq2;
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  const blocked = pq2Blocked(pq2);
  const scan = async (wider: boolean) => {
    setBusy(true);
    try {
      const r = await core.pq2Scan(wider);
      toast(fill(p.scanFound, { n: r.found }), 'good');
      onScanned();
    } catch (err) {
      toast(errorText(codeOf(err)), 'bad');
    } finally {
      setBusy(false);
    }
  };
  const restored = pq2.blocked !== 'legacy' && (pq2.blocked === 'scan_needed' || pq2.scanned[0] > 0 || pq2.scanned[1] > 0);
  return (
    <section class="card accounts">
      <header class="card-head"><h3>{p.title}</h3><span class="badge">{m().kinds.pq2.badge}</span></header>
      <div class="card-pad">
        <p class="muted small">{p.lead}</p>
        {blocked && <Notice tone={pq2.blocked === 'legacy' ? 'warn' : 'info'}>{blocked}</Notice>}
      </div>
      {pq2.addresses.length > 0 && (
        <ul class="account-list">
          {pq2.addresses.map((a) => (
            <li class="account">
              <span class="kind-mark kind-mldsa44"><Icon name={KIND_ICON.pq2} size={18} /></span>
              <div class="account-main">
                <div class="account-addr">
                  <Mono class="addr-text" title={a.address}>{shorten(a.address, 14, 12)}</Mono>
                  <CopyButton text={a.address} />
                </div>
                <dl class="rows compact">
                  {a.coins.map((c) => (
                    <div><dt class="num">{coins(c.sats)}</dt><dd><Chip tone={PQ2_TONE[c.status]} dot>{p[`status_${c.status}`]}</Chip></dd></div>
                  ))}
                </dl>
              </div>
              <div class="account-side">
                <Amount sats={a.spendable} />
                {a.incoming > 0 && <small class="muted num">+{coins(a.incoming)}</small>}
              </div>
            </li>
          ))}
        </ul>
      )}
      {pq2.addresses.length > 0 && <div class="card-pad"><p class="faint small">{p.statusHelp}</p></div>}
      {restored && (
        <div class="card-pad">
          <h4>{p.scanTitle}</h4>
          {pq2.blocked !== 'scan_needed' && <p class="muted small">{fill(p.scanned, { r: pq2.scanned[0], c: pq2.scanned[1] })}</p>}
          <div class="row-actions">
            <Button size="sm" icon="refresh" busy={busy} onClick={() => scan(pq2.blocked !== 'scan_needed')}>
              {busy ? p.scanning : pq2.blocked === 'scan_needed' ? p.scan : p.scanWider}
            </Button>
          </div>
        </div>
      )}
    </section>
  );
}

/**
 * Opens the faucet in the browser with one of this wallet's addresses filled in, or with none when there is
 * no address to give; the toast says the address is there once the page has opened.
 */
export async function openFaucet(address: string | undefined, toast: (text: string, tone?: 'good' | 'bad' | 'neutral') => void) {
  try {
    await core.openPage('faucet', address);
    if (address) toast(m().common.faucetOpened, 'good');
  } catch (err) {
    toast(errorText(codeOf(err)), 'bad');
  }
}

/**
 * A wallet restored from a web wallet backup code may have a seed made from an EVM signature (the web
 * wallet's sign-in), which someone able to break that signature's curve could recompute.
 */
export function LegacyNotice() {
  const o = m().overview;
  return <Notice tone="warn"><strong>{o.legacyTitle}</strong><p>{o.legacyBody}</p></Notice>;
}

function AccountRow({ account, chain }: { account: AccountView; chain: Chain | null }) {
  const k = m().kinds[account.kind];
  const st = statusOf(account, chain);
  return (
    <li class={`account${account.shown ? '' : ' account-waiting'}`}>
      <span class={`kind-mark kind-${account.kind}`}><Icon name={KIND_ICON[account.kind]} size={18} /></span>
      <div class="account-main">
        <div class="account-title"><strong>{k.title}</strong><span class="badge">{k.badge}</span></div>
        <p class="account-body">{k.body}</p>
        <div class="account-addr">
          {account.shown ? (
            <>
              <Mono class="addr-text" title={account.address}>{shorten(account.address, 14, 12)}</Mono>
              <CopyButton text={account.address} />
            </>
          ) : (
            <span class="faint small inline-icon"><Icon name="lock" size={13} />{m().overview.addressLater}</span>
          )}
        </div>
      </div>
      <div class="account-side">
        <Amount sats={account.spendable} />
        {account.incoming > 0 && <small class="muted num">+{coins(account.incoming)}</small>}
        <Chip tone={st.tone} dot>{st.text}</Chip>
      </div>
    </li>
  );
}

function NetworkCard({ chain, fetched }: { chain: Chain; fetched: number }) {
  const o = m().overview;
  const tripwire = chain.ec_disabled === null ? o.tripwireUnknown : chain.ec_disabled ? o.tripwireOn : o.tripwireOff;
  const milestone = (h: number | null) => (h === null ? '—' : chain.tip >= h ? fill(o.activeFrom, { n: group(h) }) : fill(o.waitingFor, { n: group(h) }));
  return (
    <Card class="network" title={<><span class="pulse" />{m().app.network}</>} actions={<span class="faint small">{fill(o.updated, { when: ago(fetched) })}</span>}>
      <dl class="facts">
        <div><dt>{o.tip}</dt><dd class="num">{group(chain.tip)}</dd></div>
        <div><dt>{o.m1}</dt><dd>{milestone(chain.mldsa44_height)}</dd></div>
        <div><dt>{o.m3}</dt><dd>{milestone(chain.tripwire_height)} · <span class={chain.ec_disabled ? 'tone-warn' : ''}>{tripwire}</span></dd></div>
        {chain.lattice_height !== null && <div><dt>{m().pq2.network}</dt><dd>{milestone(chain.lattice_height + 6)}</dd></div>}
      </dl>
    </Card>
  );
}
