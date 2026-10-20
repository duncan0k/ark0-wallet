// What this wallet sent, and how big each signature made it.
import { useEffect, useState } from 'preact/hooks';
import { core, type AppInfo, type Sent } from '../api';
import { Button, Chip, CompareBars, CopyButton, Icon, Mono, Notice } from '../components';
import { errorText, fill, m } from '../i18n';
import { ago, amount, coins, group, ms, shorten } from '../format';

export function Activity({ info, version }: { info: AppInfo | null; version: number }) {
  const [list, setList] = useState<Sent[] | null>(null);
  const [open, setOpen] = useState<string | null>(null);
  useEffect(() => {
    core.activity().then(setList).catch(() => setList([]));
  }, [version]);
  if (list === null) return <div class="page"><div class="skeleton-card" /></div>;
  if (list.length === 0) return <div class="page"><Notice tone="info">{m().activity.empty}</Notice></div>;
  return (
    <div class="page">
      <ul class="tx-list">
        {list.map((s) => (
          <li class={`tx${open === s.txid ? ' open' : ''}`}>
            <button class="tx-row" onClick={() => setOpen(open === s.txid ? null : s.txid)}>
              <span class="tx-icon"><Icon name="send" size={16} /></span>
              <span class="tx-main">
                <strong>{m().activity.to} <Mono>{shorten(s.to, 10, 6)}</Mono></strong>
                <small class="muted">{ago(s.created)} · {s.signature === 'mldsa44' ? 'ML-DSA-44' : 'Schnorr'}</small>
              </span>
              <span class="tx-amount num">−{coins(s.send)}</span>
              <StatusChip s={s} />
              <span class="tx-chevron"><Icon name="chevron" size={16} /></span>
            </button>
            {open === s.txid && <Details s={s} info={info} />}
          </li>
        ))}
      </ul>
    </div>
  );
}

function StatusChip({ s }: { s: Sent }) {
  const a = m().activity;
  if (s.status === 'confirmed') return <Chip tone={s.proof_verified ? 'good' : 'accent'}>{s.proof_verified || !s.doubted ? fill(a.status_confirmed, { n: s.confirmations }) : a.status_unproven}</Chip>;
  if (s.status === 'mempool') return <Chip tone="accent">{a.status_mempool}</Chip>;
  if (s.status === 'rejected') return <Chip tone="bad">{a.status_rejected}</Chip>;
  if (s.status === 'failed') return <Chip tone="bad">{a.status_failed}</Chip>;
  if (s.status === 'submitting') return <Chip tone="neutral">{a.status_submitting}</Chip>;
  if (s.status === 'replaced') return <Chip tone="neutral">{a.status_replaced}</Chip>;
  return <Chip tone="warn">{a.status_unknown}</Chip>;
}

function Details({ s, info }: { s: Sent; info: AppInfo | null }) {
  const a = m().activity;
  const schnorr = info?.costs.find((c) => c.kind === 'schnorr');
  const mine = info?.costs.find((c) => c.kind === (s.from === 'mixed' ? 'mixed' : s.from) && c.signature === s.signature);
  return (
    <div class="tx-details">
      <dl class="rows">
        <div><dt>{a.txid}</dt><dd class="txid-line"><Mono class="break">{s.txid}</Mono><CopyButton text={s.txid} />
          <Button kind="ghost" size="sm" icon="external" onClick={() => core.openPage('tx', s.txid)} title={m().common.explorer} /></dd></div>
        <div><dt>{m().send.rowTo}</dt><dd><Mono class="break">{s.to}</Mono></dd></div>
        <div><dt>{m().send.rowFee}</dt><dd>{amount(s.fee)}</dd></div>
        <div><dt>{m().send.rowSize}</dt><dd class="num">{group(s.vsize)} vB · {group(s.size)} B</dd></div>
        <div><dt>{m().send.rowSignature}</dt><dd>{s.signature === 'mldsa44' ? 'ML-DSA-44 · FIPS 204' : 'Schnorr · BIP-340'} · {fill(m().send.signedIn, { ms: ms(s.sign_ms) })}</dd></div>
      </dl>
      {s.reason && s.status === 'rejected' && <pre class="node-says">{s.reason}</pre>}
      {s.reason && s.status === 'failed' && <p class="faint small">{errorText(s.reason)}</p>}
      {s.status === 'replaced' && <p class="faint small">{a.replacedNote}</p>}
      {s.signature === 'mldsa44' && mine && schnorr && (
        <div class="compare">
          <h4>{a.signatureCompare}</h4>
          <CompareBars rows={[
            { label: a.thisSpend, bytes: mine.signature_bytes, vsize: mine.tx_vsize, tone: 'accent' },
            { label: a.sameWithSchnorr, bytes: schnorr.signature_bytes, vsize: schnorr.tx_vsize, tone: 'neutral' },
          ]} />
          <p class="faint small compare-note">{a.onChain}</p>
        </div>
      )}
    </div>
  );
}
