// Before the wallet is open: the welcome screen, making a wallet, restoring one, and unlocking.
import type { ComponentChildren } from 'preact';
import { useEffect, useLayoutEffect, useMemo, useRef, useState } from 'preact/hooks';
import { codeOf, core, type Status } from '../api';
import { Brand, Button, Field, Icon, Modal, Notice, PasswordInput, StrengthMeter, Text } from '../components';
import { errorText, fill, locale, m } from '../i18n';

const MIN = 8;

const FEATURE_ICONS = ['drill', 'lock', 'leaf'];

/** Every screen before the wallet is open: the brand and what the wallet does on the left, the step on the right. */
export function Frame({ children, onBack, wide }: { children: ComponentChildren; onBack?: () => void; wide?: boolean }) {
  const w = m().welcome;
  return (
    <div class="onboard">
      <aside class="onboard-brand">
        <Brand size={36} />
        <div class="brand-copy">
          <h2><Text>{w.headline}</Text></h2>
          <ul class="features">
            {w.features.map((f, i) => (
              <li>
                <span class="feature-icon"><Icon name={FEATURE_ICONS[i] ?? 'check'} size={17} /></span>
                <div><strong>{f.title}</strong><span><Text>{f.body}</Text></span></div>
              </li>
            ))}
          </ul>
        </div>
        <p class="brand-foot">{m().app.testnet}</p>
      </aside>
      <main class="onboard-main">
        <div class={`onboard-panel${wide ? ' onboard-wide' : ''}`}>
          {onBack && (
            <button class="back-link" onClick={onBack}>
              <span class="flip"><Icon name="chevron" size={16} /></span>
              {m().common.back}
            </button>
          )}
          {children}
          <p class="onboard-foot">{m().app.testnet}</p>
        </div>
      </main>
    </div>
  );
}

function Head({ title, lead }: { title: string; lead?: string }) {
  return (
    <div class="onboard-head">
      <h1>{title}</h1>
      {lead && <p class="lead">{lead}</p>}
    </div>
  );
}

export function Welcome({ onCreate, onRestore }: { onCreate: () => void; onRestore: () => void }) {
  return (
    <Frame>
      <Head title={m().welcome.title} lead={m().welcome.lead} />
      <div class="choice-list">
        <button class="choice" onClick={onCreate}>
          <span class="choice-icon"><Icon name="plus" size={20} /></span>
          <span class="choice-text"><strong>{m().welcome.create}</strong><small>{m().welcome.createHint}</small></span>
          <Icon name="chevron" />
        </button>
        <button class="choice" onClick={onRestore}>
          <span class="choice-icon"><Icon name="restore" size={20} /></span>
          <span class="choice-text"><strong>{m().welcome.restore}</strong><small>{m().welcome.restoreHint}</small></span>
          <Icon name="chevron" />
        </button>
      </div>
    </Frame>
  );
}

function Steps({ steps, at }: { steps: readonly string[]; at: number }) {
  return (
    <ol class="steps">
      {steps.map((s, i) => (
        <li class={i < at ? 'done' : i === at ? 'now' : ''}>
          <span class="step-dot">{i < at ? <Icon name="check" size={13} /> : i + 1}</span>
          <span class="step-name">{s}</span>
        </li>
      ))}
    </ol>
  );
}

function PasswordForm({ busyText, submitText, onSubmit, hint }: { busyText: string; submitText: string; hint: string; onSubmit: (p: string) => Promise<void> }) {
  const [p1, setP1] = useState('');
  const [p2, setP2] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const mismatch = p2.length > 0 && p1 !== p2;
  // Characters as the core counts them (code points), not UTF-16 units.
  const ok = [...p1].length >= MIN && p1 === p2;
  const submit = async (e: Event) => {
    e.preventDefault();
    if (!ok) return;
    setBusy(true);
    setError(null);
    try {
      await onSubmit(p1);
    } catch (err) {
      setError(errorText(codeOf(err)));
      setBusy(false);
    }
  };
  return (
    <form onSubmit={submit} class="stack">
      <p class="muted">{hint}</p>
      <Field label={m().common.password} id="pw1">
        <PasswordInput id="pw1" value={p1} onInput={setP1} autoFocus autocomplete="new-password" />
        <StrengthMeter password={p1} />
      </Field>
      <Field label={m().common.confirmPassword} id="pw2" error={mismatch ? m().password.mismatch : null}>
        <PasswordInput id="pw2" value={p2} onInput={setP2} autocomplete="new-password" />
      </Field>
      {error && <Notice tone="bad">{error}</Notice>}
      <Button kind="primary" size="lg" type="submit" disabled={!ok} busy={busy} block>
        {busy ? busyText : submitText}
      </Button>
    </form>
  );
}

/** Three distinct positions in 0..23, in order. */
function pickPositions(): number[] {
  const set = new Set<number>();
  const r = new Uint32Array(8);
  while (set.size < 3) {
    crypto.getRandomValues(r);
    for (const x of r) if (set.size < 3) set.add(x % 24);
  }
  return [...set].sort((a, b) => a - b);
}

export function CreateFlow({ onDone, onBack }: { onDone: (s: Status) => void; onBack: () => void }) {
  const steps = m().create.steps;
  const [step, setStep] = useState(0);
  const [agreed, setAgreed] = useState(false);
  const [words, setWords] = useState<string[]>([]);
  const [revealed, setRevealed] = useState(false);
  const positions = useMemo(pickPositions, [words]);
  const [answers, setAnswers] = useState<string[]>(['', '', '']);
  const [checkError, setCheckError] = useState<string | null>(null);
  const [checking, setChecking] = useState(false);
  const [creating, setCreating] = useState(false);
  const [createError, setCreateError] = useState<string | null>(null);
  const active = useRef(true);

  // Drop the core's pending secret as well as the words when this flow is left.
  useLayoutEffect(() => () => {
    active.current = false;
    setWords([]);
    core.cancelNewWallet();
  }, []);

  const toWords = async () => {
    setCreating(true);
    setCreateError(null);
    try {
      const next = await core.newPhrase();
      if (!active.current) {
        await core.cancelNewWallet();
        return;
      }
      setWords(next);
      setRevealed(false);
      setStep(1);
    } catch (err) {
      if (active.current) setCreateError(errorText(codeOf(err)));
    } finally {
      if (active.current) setCreating(false);
    }
  };

  const check = async (e: Event) => {
    e.preventDefault();
    setChecking(true);
    setCheckError(null);
    try {
      await core.confirmPhrase(positions, answers.map((a) => a.trim().toLowerCase()));
      setStep(3);
    } catch (err) {
      setCheckError(errorText(codeOf(err)));
    } finally {
      setChecking(false);
    }
  };

  return (
    <Frame onBack={step === 0 ? onBack : () => setStep(step === 3 ? 2 : step - 1)} wide={step === 1}>
      <Head title={m().create.title} />
      <Steps steps={steps} at={step} />
      {step === 0 && (
        <div class="stack">
          <h2 class="subtitle">{m().create.introTitle}</h2>
          <ol class="rules">{m().create.intro.map((r) => <li>{r}</li>)}</ol>
          <label class="check">
            <input type="checkbox" checked={agreed} onChange={(e) => setAgreed((e.target as HTMLInputElement).checked)} />
            <span>{m().create.understood}</span>
          </label>
          {createError && <Notice tone="bad">{createError}</Notice>}
          <Button kind="primary" size="lg" busy={creating} disabled={!agreed} onClick={toWords} block>{m().common.continue}</Button>
        </div>
      )}
      {step === 1 && (
        <div class="stack">
          <div class={`words${revealed ? '' : ' words-hidden'}`}>
            {words.map((w, i) => <div class="word"><span class="word-n">{i + 1}</span><span class="word-w">{w}</span></div>)}
            {!revealed && (
              <div class="words-cover">
                <Button kind="secondary" icon="eye" onClick={() => setRevealed(true)}>{m().create.reveal}</Button>
                <small>{m().create.revealHint}</small>
              </div>
            )}
          </div>
          <Button kind="primary" size="lg" disabled={!revealed} onClick={() => { setAnswers(['', '', '']); setStep(2); }} block>{m().create.wroteDown}</Button>
        </div>
      )}
      {step === 2 && (
        <form class="stack" onSubmit={check}>
          <h2 class="subtitle">{m().create.confirmTitle}</h2>
          <p class="muted">{m().create.confirmHint}</p>
          <div class="confirm-grid">
            {positions.map((p, i) => (
              <Field label={fill(m().create.word, { n: p + 1 })} id={`w${i}`}>
                <input id={`w${i}`} class="input mono" autocomplete="off" spellcheck={false} value={answers[i]}
                  onInput={(e) => { const a = [...answers]; a[i] = (e.target as HTMLInputElement).value; setAnswers(a); }} />
              </Field>
            ))}
          </div>
          {checkError && <Notice tone="bad">{checkError}</Notice>}
          <Button kind="primary" size="lg" type="submit" busy={checking} disabled={answers.some((a) => !a.trim())} block>{m().common.continue}</Button>
        </form>
      )}
      {step === 3 && (
        <PasswordForm hint={m().create.passwordHint} submitText={m().create.create} busyText={m().create.creating}
          onSubmit={async (p) => { const s = await core.createWallet(p); setWords([]); onDone(s); }} />
      )}
    </Frame>
  );
}

export function RestoreFlow({ onDone, onBack }: { onDone: (s: Status) => void; onBack: () => void }) {
  const [text, setText] = useState('');
  const [kind, setKind] = useState<'phrase' | 'legacy' | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [step, setStep] = useState(0);

  useEffect(() => {
    if (!text.trim()) {
      setKind(null);
      setError(null);
      return;
    }
    const timer = setTimeout(async () => {
      try {
        const r = await core.checkRecovery(text);
        setKind(r.legacy ? 'legacy' : 'phrase');
        setError(null);
      } catch (err) {
        setKind(null);
        // Only say what is wrong once it looks finished: 24 words, or a code of full length.
        const words = text.trim().split(/\s+/).length;
        const looksDone = words >= 24 || text.replace(/\s+/g, '').length >= 80;
        setError(looksDone ? errorText(codeOf(err)) : null);
      }
    }, 250);
    return () => clearTimeout(timer);
  }, [text]);

  return (
    <Frame onBack={step === 0 ? onBack : () => setStep(0)}>
      <Head title={m().restore.title} />
      {step === 0 && (
        <div class="stack">
          <Field label={m().restore.label} id="recovery" error={error}>
            <textarea id="recovery" class="input mono textarea" rows={5} spellcheck={false} autocomplete="off" placeholder={m().restore.placeholder}
              value={text} onInput={(e) => setText((e.target as HTMLTextAreaElement).value)} />
          </Field>
          {kind && <Notice tone="good">{kind === 'legacy' ? m().restore.detectedLegacy : m().restore.detectedPhrase}</Notice>}
          {kind === 'legacy' && <Notice tone="warn">{m().overview.legacyBody}</Notice>}
          <Button kind="primary" size="lg" disabled={!kind} onClick={() => setStep(1)} block>{m().restore.next}</Button>
        </div>
      )}
      {step === 1 && (
        <PasswordForm hint={m().create.passwordHint} submitText={m().restore.restore} busyText={m().create.creating}
          onSubmit={async (p) => { const s = await core.restoreWallet(text, p); setText(''); onDone(s); }} />
      )}
    </Frame>
  );
}

export function Unlock({ onDone, onForgotten }: { onDone: (s: Status) => void; onForgotten: (s: Status) => void }) {
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [forget, setForget] = useState(false);
  const submit = async (e: Event) => {
    e.preventDefault();
    if (!password) return;
    setBusy(true);
    setError(null);
    try {
      onDone(await core.unlock(password));
    } catch (err) {
      setError(errorText(codeOf(err)));
      setBusy(false);
    }
  };
  return (
    <Frame>
      <Head title={m().unlock.welcome} lead={m().unlock.hint} />
      <form onSubmit={submit} class="stack">
        <Field label={m().common.password} id="unlock" error={error}>
          <PasswordInput id="unlock" value={password} onInput={setPassword} autoFocus />
        </Field>
        <Button kind="primary" size="lg" type="submit" busy={busy} disabled={!password} block>{busy ? m().unlock.unlocking : m().unlock.unlock}</Button>
        <button type="button" class="text-link center" onClick={() => setForget(true)}>{m().unlock.forgot}</button>
      </form>
      {forget && <ForgetDialog onClose={() => setForget(false)} onForgotten={onForgotten} />}
    </Frame>
  );
}

function ForgetDialog({ onClose, onForgotten }: { onClose: () => void; onForgotten: (s: Status) => void }) {
  const [typed, setTyped] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const remove = async () => {
    setBusy(true);
    setError(null);
    try {
      onForgotten(await core.forgetWallet(locale()));
    } catch (err) {
      if (codeOf(err) !== 'cancelled') setError(errorText(codeOf(err)));
      setBusy(false);
    }
  };
  const ref = useRef<HTMLInputElement>(null);
  useEffect(() => ref.current?.focus(), []);
  const ok = typed.trim().toLowerCase() === m().unlock.forgetWord.toLowerCase();
  return (
    <Modal title={m().unlock.forgetTitle} onClose={onClose}
      footer={<>
        <Button kind="ghost" onClick={onClose}>{m().common.cancel}</Button>
        <Button kind="danger" disabled={!ok} busy={busy} onClick={remove}>{m().unlock.forget}</Button>
      </>}>
      <Notice tone="warn">{m().unlock.forgetBody}</Notice>
      <Field label={m().unlock.forgetConfirm} id="forget" error={error}>
        <input ref={ref} id="forget" class="input" value={typed} onInput={(e) => setTyped((e.target as HTMLInputElement).value)} />
      </Field>
    </Modal>
  );
}
