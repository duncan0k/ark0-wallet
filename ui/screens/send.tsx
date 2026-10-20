// Sending: choose an address, a destination and an amount; the core plans it, the user reviews the plan,
// and only that plan is signed and sent. Beside the form, what the chosen address's signature costs.
import { useEffect, useRef, useState } from 'preact/hooks';
import { codeOf, core, type AccountView, type AppInfo, type Kind, type Overview, type SendPlan, type SendResult } from '../api';
import { Amount, Button, CompareBars, CopyButton, Field, Icon, Modal, Mono, Notice, useToast } from '../components';
import { errorText, fill, locale, m } from '../i18n';
import { amount as withUnit, coins, group, ms, unit, unitOfCoins } from '../format';
import { ORDER } from './overview';

const SIGNATURE_NAME = { mldsa44: 'ML-DSA-44 · FIPS 204', schnorr: 'Schnorr · BIP-340' };

export function Send({ data, info, onSent, onActivity, preferred }: {
  data: Overview | null;
  info: AppInfo | null;
  onSent: () => void;
  onActivity: () => void;
  preferred?: Kind;
}) {
  const usable = ORDER.map((k) => data?.accounts.find((a) => a.kind === k)).filter((a): a is AccountView => !!a && a.shown);
  const [from, setFrom] = useState<Kind | null>(null);
  const [to, setTo] = useState('');
  const [amount, setAmount] = useState('');
  const [all, setAll] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [plan, setPlan] = useState<SendPlan | null>(null);
  const [result, setResult] = useState<SendResult | null>(null);
  const toInput = useRef<HTMLInputElement>(null);
  const toast = useToast();

  useEffect(() => {
    if (from === null || !usable.some((a) => a.kind === from)) {
      const pick = usable.find((a) => a.kind === preferred && a.spendable > 0) ?? usable.find((a) => a.spendable > 0) ?? usable[0];
      if (pick) setFrom(pick.kind);
    }
  }, [data]);

  if (!data) return <div class="page"><div class="skeleton-card" /></div>;
  if (usable.length === 0) return <div class="page narrow"><Notice tone="info">{m().send.nothingToSend}</Notice></div>;
  const source = usable.find((a) => a.kind === from) ?? usable[0]!;

  const review = async (e: Event) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      setPlan(await core.planSend(source.kind, to.trim(), all ? 'all' : amount.trim()));
    } catch (err) {
      setError(errorText(codeOf(err)));
    } finally {
      setBusy(false);
    }
  };

  // Some webviews refuse to read the clipboard or never answer; then the field takes the keyboard paste.
  const paste = async () => {
    const text = await Promise.race([
      navigator.clipboard.readText().catch(() => null),
      new Promise<null>((r) => setTimeout(() => r(null), 1200)),
    ]);
    if (text) {
      setTo(text.trim());
    } else {
      toInput.current?.focus();
      toast(fill(m().send.pasteHint, { keys: /Mac/.test(navigator.userAgent) ? '⌘V' : 'Ctrl+V' }));
    }
  };

  if (result) {
    return (
      <div class="page narrow">
        <ResultPanel result={result} onActivity={onActivity}
          onAgain={() => { setResult(null); setPlan(null); setTo(''); setAmount(''); setAll(false); }} />
      </div>
    );
  }

  return (
    <div class="page">
      <div class="send-grid">
        <form class="card form-card stack" onSubmit={review}>
          <Field label={m().send.from}>
            <div class="source-list" role="radiogroup">
              {usable.map((a) => (
                <button type="button" role="radio" aria-checked={a.kind === source.kind} class={`source${a.kind === source.kind ? ' selected' : ''}`} onClick={() => setFrom(a.kind)}>
                  <span class="source-title">{m().kinds[a.kind].title}</span>
                  <span class="badge">{m().kinds[a.kind].badge}</span>
                  <span class="source-amount"><Amount sats={a.spendable} /></span>
                </button>
              ))}
            </div>
          </Field>
          <Field label={m().send.to} id="to">
            <div class="input-wrap">
              <input ref={toInput} id="to" class="input mono" placeholder={m().send.toPlaceholder} spellcheck={false} autocomplete="off" value={to}
                onInput={(e) => setTo((e.target as HTMLInputElement).value)} />
              <button type="button" class="input-affix" onClick={paste}><Icon name="paste" size={15} />{m().send.paste}</button>
            </div>
          </Field>
          <Field label={m().send.amount} id="amount" hint={m().send.feeNote}>
            <div class="input-wrap">
              <input id="amount" class="input num" inputMode="decimal" placeholder="0.00" disabled={all} value={all ? coins(source.spendable) : amount}
                onInput={(e) => setAmount((e.target as HTMLInputElement).value)} />
              <span class="input-unit">{all ? unit(source.spendable) : unitOfCoins(amount.trim() ? Number(amount) : NaN)}</span>
              <button type="button" class={`input-affix${all ? ' on' : ''}`} onClick={() => setAll(!all)}>{m().send.max}</button>
            </div>
          </Field>
          {error && <Notice tone="bad">{error}</Notice>}
          <Button kind="primary" size="lg" type="submit" busy={busy} disabled={!to.trim() || (!all && !amount.trim())} block>
            {busy ? m().send.reviewing : m().send.review}
          </Button>
        </form>
        <Summary source={source} info={info} />
      </div>
      {plan && <ReviewDialog plan={plan} all={all} onClose={() => setPlan(null)} onSent={(r) => { setPlan(null); setResult(r); onSent(); }} />}
    </div>
  );
}

/** What a payment from the chosen address costs: its signature, the size of one input, the fee. */
function Summary({ source, info }: { source: AccountView; info: AppInfo | null }) {
  const s = m().send;
  const path = source.path ?? (source.kind === 'schnorr' ? 'schnorr' : 'mldsa44');
  const cost = info?.costs.find((c) => c.kind === source.kind && c.signature === path);
  const pq = info?.costs.find((c) => c.kind === 'mldsa44');
  const classic = info?.costs.find((c) => c.kind === 'schnorr');
  return (
    <aside class="card summary">
      <header class="card-head"><h3>{s.summaryTitle}</h3></header>
      <dl class="rows compact">
        <div><dt>{s.sumSignature}</dt><dd>{SIGNATURE_NAME[path]}</dd></div>
        <div><dt>{s.sumSigSize}</dt><dd class="num">{cost ? fill(s.bytes, { n: group(cost.signature_bytes) }) : '—'}</dd></div>
        <div><dt>{s.sumTxSize}</dt><dd class="num">{cost ? `${group(cost.tx_vsize)} vB` : '—'}</dd></div>
        <div><dt>{s.sumFee}</dt><dd class="num">{cost && info ? fill(s.feeFrom, { amount: withUnit(cost.tx_vsize * info.fee_rate) }) : '—'}</dd></div>
      </dl>
      {pq && classic && (
        <div class="compare">
          <h4>{m().activity.signatureCompare}</h4>
          <CompareBars compact rows={[
            { label: 'ML-DSA-44', bytes: pq.signature_bytes, vsize: pq.tx_vsize, tone: 'accent' },
            { label: 'Schnorr', bytes: classic.signature_bytes, vsize: classic.tx_vsize, tone: 'neutral' },
          ]} />
        </div>
      )}
      <p class="summary-note"><Icon name="lock" size={14} />{s.localSigning}</p>
      <p class="faint small">{s.sumNote}</p>
    </aside>
  );
}

function ReviewDialog({ plan, all, onClose, onSent }: { plan: SendPlan; all: boolean; onClose: () => void; onSent: (r: SendResult) => void }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const s = m().send;
  const confirm = async () => {
    setBusy(true);
    setError(null);
    try {
      onSent(await core.confirmSend(plan.id, locale()));
    } catch (err) {
      // Cancelling the system dialog drops the plan; the form stays as it was, for another review.
      if (codeOf(err) === 'cancelled') onClose();
      else setError(errorText(codeOf(err)));
      setBusy(false);
    }
  };
  return (
    <Modal title={s.reviewTitle} onClose={busy ? () => {} : onClose}
      footer={<>
        <Button kind="ghost" onClick={onClose} disabled={busy}>{m().common.cancel}</Button>
        <Button kind="primary" icon="check" busy={busy} onClick={confirm}>{busy ? s.signing : s.confirm}</Button>
      </>}>
      <div class="review-amount">
        <span class="eyebrow">{s.rowAmount}</span>
        <Amount sats={plan.send} size="lg" />
      </div>
      <dl class="rows">
        <div><dt>{s.rowFrom}</dt><dd>{m().kinds[plan.from].title}</dd></div>
        <div><dt>{s.rowTo}</dt><dd><Mono class="break">{plan.to}</Mono></dd></div>
        <div><dt>{s.rowFee}</dt><dd>{withUnit(plan.fee)} <span class="muted">· {plan.fee_rate} sat/vB</span></dd></div>
        {plan.change > 0 && <div><dt>{s.rowChange}</dt><dd>{withUnit(plan.change)}</dd></div>}
        <div><dt>{s.rowSignature}</dt><dd>{SIGNATURE_NAME[plan.signature]}</dd></div>
        <div><dt>{s.rowSize}</dt><dd class="num">{group(plan.vsize)} vB <span class="muted">· {group(plan.size)} B</span></dd></div>
        <div><dt>{s.rowInputs}</dt><dd class="num">{plan.inputs}</dd></div>
      </dl>
      {plan.to_self && <Notice tone="info">{s.toSelf}</Notice>}
      {plan.left > 0 && <Notice tone="warn">{fill(s.leftOut, { n: plan.left })}</Notice>}
      {all && plan.truncated && <Notice tone="warn">{s.truncatedAll}</Notice>}
      {plan.went_out && <Notice tone="warn">{s.wentOut}</Notice>}
      {plan.unclear_elsewhere && <Notice tone="warn">{s.unclearElsewhere}</Notice>}
      {plan.unrecorded && <Notice tone="warn">{s.unrecorded}</Notice>}
      {plan.one_source && <Notice tone="warn">{s.oneSource}</Notice>}
      {plan.sources_disagree && <Notice tone="warn">{s.sourcesDisagree}</Notice>}
      {plan.replaces > 0 && <Notice tone="info">{plan.replaces === 1 ? s.replacesOne : fill(s.replacesMany, { n: plan.replaces })}</Notice>}
      <p class="summary-note"><Icon name="lock" size={14} />{s.localSigning}</p>
      <p class="faint small">{s.systemConfirm}</p>
      {error && <Notice tone="bad">{error}</Notice>}
    </Modal>
  );
}

function ResultPanel({ result, onAgain, onActivity }: { result: SendResult; onAgain: () => void; onActivity: () => void }) {
  const s = m().send;
  const r = result.result;
  const tone = r.kind === 'sent' ? 'good' : r.kind === 'unknown' ? 'warn' : 'bad';
  const title = r.kind === 'sent' ? s.sentTitle : r.kind === 'unknown' ? s.unknownTitle : r.kind === 'rejected' ? s.rejectedTitle : s.failedTitle;
  return (
    <section class={`card result result-${tone}`}>
      <div class="result-icon"><Icon name={tone === 'good' ? 'check' : 'alert'} size={28} /></div>
      <h2>{title}</h2>
      {r.kind === 'sent' && <p class="muted">{s.sentBody}</p>}
      {r.kind === 'unknown' && <p class="muted">{s.unknownBody}</p>}
      {r.kind === 'rejected' && <pre class="node-says">{r.reason}</pre>}
      {r.kind === 'failed' && <p class="muted">{errorText(r.error)}</p>}
      <div class="txid-box">
        <Mono title={result.txid}>{result.txid}</Mono>
        <CopyButton text={result.txid} />
        <Button kind="ghost" size="sm" icon="external" onClick={() => core.openPage('tx', result.txid)} title={m().common.explorer} />
      </div>
      <p class="faint small">{fill(s.signedIn, { ms: ms(result.sign_ms) })}</p>
      <div class="result-actions">
        <Button kind="secondary" icon="activity" onClick={onActivity}>{s.viewActivity}</Button>
        <Button kind="ghost" onClick={onAgain}>{s.another}</Button>
      </div>
    </section>
  );
}
