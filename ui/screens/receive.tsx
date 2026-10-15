// Receiving: one of the wallet's addresses, as text and as a QR code.
import { useEffect, useState } from 'preact/hooks';
import { core, type AccountView, type Kind, type Overview } from '../api';
import { Button, CopyButton, Mono, Notice } from '../components';
import { m } from '../i18n';
import { grouped } from '../format';
import { ORDER } from './overview';

export function Receive({ data }: { data: Overview | null }) {
  const shown = ORDER.map((k) => data?.accounts.find((a) => a.kind === k)).filter((a): a is AccountView => !!a && a.shown);
  const [kind, setKind] = useState<Kind>('mldsa44');
  const account = shown.find((a) => a.kind === kind) ?? shown[0];
  const [svg, setSvg] = useState<string | null>(null);

  useEffect(() => {
    setSvg(null);
    if (account) core.qrSvg(account.address).then(setSvg).catch(() => setSvg(null));
  }, [account?.address]);

  if (!data) return <div class="page"><div class="skeleton-card" /></div>;
  if (!account) return <div class="page"><Notice tone="info">{m().send.nothingToSend}</Notice></div>;

  return (
    <div class="page narrow">
      <div class="segmented" role="tablist">
        {shown.map((a) => (
          <button role="tab" aria-selected={a.kind === account.kind} class={a.kind === account.kind ? 'on' : ''} onClick={() => setKind(a.kind)}>
            {m().kinds[a.kind].title}
          </button>
        ))}
      </div>
      <section class="card receive-card">
        <div class="qr">{svg ? <div class="qr-svg" dangerouslySetInnerHTML={{ __html: svg }} /> : <div class="qr-placeholder" />}</div>
        <div class="receive-kind">
          <span class="badge">{m().kinds[account.kind].badge}</span>
          <p class="muted small">{m().kinds[account.kind].body}</p>
        </div>
        <Mono class="receive-address">{grouped(account.address)}</Mono>
        <div class="row-actions">
          <CopyButton text={account.address} label size="md" kind="secondary" />
          <Button kind="ghost" icon="external" onClick={() => core.openPage('address', account.address)}>{m().common.explorer}</Button>
        </div>
        <Notice tone="info">{m().receive.hint}</Notice>
      </section>
    </div>
  );
}
