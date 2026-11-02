// Receiving: one of the wallet's addresses, as text and as a QR code.
import { useEffect, useState } from 'preact/hooks';
import { codeOf, core, type AccountView, type FixedKind, type Overview, type Pq2View } from '../api';
import { Button, CopyButton, Mono, Notice } from '../components';
import { errorText, m } from '../i18n';
import { grouped } from '../format';
import { ORDER, pq2Blocked } from './overview';

export function Receive({ data }: { data: Overview | null }) {
  const shown = ORDER.map((k) => data?.accounts.find((a) => a.kind === k)).filter((a): a is AccountView => !!a && a.shown);
  const [kind, setKind] = useState<FixedKind>('mldsa44');
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
      {data.pq2 && <Pq2Receive pq2={data.pq2} />}
    </div>
  );
}

/**
 * A pq2 address is shown once, when asked for: the core records it as handed out before it answers, and
 * never gives it again. Until one may be handed out, this says why not yet.
 */
function Pq2Receive({ pq2 }: { pq2: Pq2View }) {
  const p = m().pq2;
  const [address, setAddress] = useState<string | null>(null);
  const [svg, setSvg] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const blocked = pq2Blocked(pq2);
  const ask = async () => {
    setBusy(true);
    setError(null);
    try {
      const a = await core.pq2NewAddress();
      setAddress(a.address);
      core.qrSvg(a.address).then(setSvg).catch(() => setSvg(null));
    } catch (err) {
      setError(errorText(codeOf(err)));
    } finally {
      setBusy(false);
    }
  };
  return (
    <section class="card receive-card">
      <div class="receive-kind">
        <span class="badge">{m().kinds.pq2.badge}</span>
        <p class="muted small">{m().kinds.pq2.body}</p>
      </div>
      {blocked ? (
        <Notice tone={pq2.blocked === 'legacy' ? 'warn' : 'info'}>{blocked}</Notice>
      ) : address ? (
        <>
          <div class="qr">{svg ? <div class="qr-svg" dangerouslySetInnerHTML={{ __html: svg }} /> : <div class="qr-placeholder" />}</div>
          <Mono class="receive-address">{grouped(address)}</Mono>
          <div class="row-actions"><CopyButton text={address} label size="md" kind="secondary" /></div>
          <Notice tone="warn">{p.shownOnce}</Notice>
        </>
      ) : (
        <p class="muted small">{p.newHint}</p>
      )}
      {!blocked && <div class="row-actions"><Button kind={address ? 'ghost' : 'primary'} icon="plus" busy={busy} onClick={ask}>{p.newAddress}</Button></div>}
      {error && <Notice tone="bad">{error}</Notice>}
    </section>
  );
}
