// Settings: language, the idle lock, the password, the recovery words, removing the wallet, and the
// signing core's self-test.
import type { ComponentChildren } from 'preact';
import { useState } from 'preact/hooks';
import { codeOf, core, type AppInfo, type SelftestReport, type Settings as SettingsData, type Status } from '../api';
import { Button, Card, Field, Modal, Mono, Notice, PasswordInput, StrengthMeter, useToast } from '../components';
import { errorText, fill, m } from '../i18n';
import { ms } from '../format';

const LOCK_CHOICES = [5, 15, 30, 60, 0];

export function Settings({ settings, info, onSettings, onRemoved }: {
  settings: SettingsData;
  info: AppInfo | null;
  onSettings: (s: SettingsData) => void;
  onRemoved: (s: Status) => void;
}) {
  const st = m().settings;
  const toast = useToast();
  const [dialog, setDialog] = useState<'recovery' | 'password' | 'remove' | null>(null);
  const save = async (next: SettingsData) => {
    try {
      onSettings(await core.settingsSet(next));
      toast(st.saved, 'good');
    } catch (err) {
      toast(errorText(codeOf(err)), 'bad');
    }
  };
  return (
    <div class="page narrow">
      <Card title={st.language}>
        <div class="segmented">
          {(['auto', 'zh-Hans', 'zh-Hant', 'en'] as const).map((l) => (
            <button class={settings.language === l ? 'on' : ''} onClick={() => save({ ...settings, language: l })}>
              {l === 'auto' ? st.languageAuto : l === 'zh-Hans' ? '简体中文' : l === 'zh-Hant' ? '繁體中文' : 'English'}
            </button>
          ))}
        </div>
      </Card>
      <Card title={st.autoLock}>
        <div class="segmented">
          {LOCK_CHOICES.map((n) => (
            <button class={settings.auto_lock_minutes === n ? 'on' : ''} onClick={() => save({ ...settings, auto_lock_minutes: n })}>
              {n === 0 ? st.autoLockNever : fill(st.autoLockMinutes, { n })}
            </button>
          ))}
        </div>
      </Card>
      <Card title={st.security}>
        <div class="setting-rows">
          <SettingRow title={st.showRecovery} hint={st.showRecoveryHint} action={<Button onClick={() => setDialog('recovery')}>{m().common.show}</Button>} />
          <SettingRow title={st.changePassword} action={<Button onClick={() => setDialog('password')}>{st.changePassword}</Button>} />
          <SettingRow title={st.remove} hint={st.removeHint} action={<Button kind="danger" onClick={() => setDialog('remove')}>{m().unlock.forget}</Button>} />
        </div>
      </Card>
      <SelftestCard />
      <Card title={st.about}>
        <dl class="rows">
          <div><dt>{st.version}</dt><dd>{info?.version ?? '—'} <span class="muted">· {info?.target}</span></dd></div>
          <div><dt>{st.api}</dt><dd><Mono>{info?.api ?? '—'}</Mono></dd></div>
          <div><dt>{st.core}</dt><dd>{st.coreValue}</dd></div>
        </dl>
        <p class="muted small">{m().app.testnet}</p>
      </Card>
      {dialog === 'recovery' && <RecoveryDialog onClose={() => setDialog(null)} />}
      {dialog === 'password' && <PasswordDialog onClose={() => setDialog(null)} />}
      {dialog === 'remove' && <RemoveDialog onClose={() => setDialog(null)} onRemoved={onRemoved} />}
    </div>
  );
}

function SettingRow({ title, hint, action }: { title: string; hint?: string; action: ComponentChildren }) {
  return (
    <div class="setting-row">
      <div><strong>{title}</strong>{hint && <small class="muted">{hint}</small>}</div>
      {action}
    </div>
  );
}

function RecoveryDialog({ onClose }: { onClose: () => void }) {
  const [password, setPassword] = useState('');
  const [words, setWords] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const reveal = async (e: Event) => {
    e.preventDefault();
    setBusy(true);
    try {
      setWords(await core.revealRecovery(password));
      setError(null);
    } catch (err) {
      setError(errorText(codeOf(err)));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal title={m().settings.showRecovery} onClose={() => { setWords(null); onClose(); }} wide={words !== null}>
      <Notice tone="warn">{m().settings.recoveryWarning}</Notice>
      {words === null ? (
        <form class="stack" onSubmit={reveal}>
          <Field label={m().common.password} id="rpw" error={error}><PasswordInput id="rpw" value={password} onInput={setPassword} autoFocus /></Field>
          <Button kind="primary" type="submit" busy={busy} disabled={!password}>{m().common.show}</Button>
        </form>
      ) : words.startsWith('ark0w1-') ? (
        <pre class="node-says mono">{words}</pre>
      ) : (
        <div class="words">{words.split(' ').map((w, i) => <div class="word"><span class="word-n">{i + 1}</span><span class="word-w">{w}</span></div>)}</div>
      )}
    </Modal>
  );
}

function PasswordDialog({ onClose }: { onClose: () => void }) {
  const [old, setOld] = useState('');
  const [p1, setP1] = useState('');
  const [p2, setP2] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const toast = useToast();
  const ok = old && [...p1].length >= 8 && p1 === p2;
  const submit = async (e: Event) => {
    e.preventDefault();
    setBusy(true);
    try {
      await core.changePassword(old, p1);
      toast(m().settings.saved, 'good');
      onClose();
    } catch (err) {
      setError(errorText(codeOf(err)));
      setBusy(false);
    }
  };
  return (
    <Modal title={m().settings.changePassword} onClose={onClose}>
      <form class="stack" onSubmit={submit}>
        <Field label={m().settings.oldPassword} id="old"><PasswordInput id="old" value={old} onInput={setOld} autoFocus /></Field>
        <Field label={m().settings.newPassword} id="new"><PasswordInput id="new" value={p1} onInput={setP1} autocomplete="new-password" /><StrengthMeter password={p1} /></Field>
        <Field label={m().common.confirmPassword} id="new2" error={p2 && p1 !== p2 ? m().password.mismatch : null}><PasswordInput id="new2" value={p2} onInput={setP2} autocomplete="new-password" /></Field>
        {error && <Notice tone="bad">{error}</Notice>}
        <Button kind="primary" type="submit" busy={busy} disabled={!ok}>{m().settings.changePassword}</Button>
      </form>
    </Modal>
  );
}

function RemoveDialog({ onClose, onRemoved }: { onClose: () => void; onRemoved: (s: Status) => void }) {
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const submit = async (e: Event) => {
    e.preventDefault();
    setBusy(true);
    try {
      onRemoved(await core.deleteWallet(password));
    } catch (err) {
      setError(errorText(codeOf(err)));
      setBusy(false);
    }
  };
  return (
    <Modal title={m().unlock.forgetTitle} onClose={onClose}>
      <form class="stack" onSubmit={submit}>
        <Notice tone="warn">{m().unlock.forgetBody}</Notice>
        <Field label={m().common.password} id="dpw" error={error}><PasswordInput id="dpw" value={password} onInput={setPassword} autoFocus /></Field>
        <Button kind="danger" type="submit" busy={busy} disabled={!password}>{m().unlock.forget}</Button>
      </form>
    </Modal>
  );
}

/** A check's name in the interface's language; a name the interface does not know stays as the core gave it. */
function label(names: Record<string, string>, name: string): string {
  return names[name] ?? name;
}

function SelftestCard() {
  const st = m().settings;
  const [report, setReport] = useState<SelftestReport | null>(null);
  const [busy, setBusy] = useState(false);
  const run = async () => {
    setBusy(true);
    try {
      setReport(await core.selftest());
    } finally {
      setBusy(false);
    }
  };
  return (
    <Card title={st.selftest} actions={<Button size="sm" busy={busy} onClick={run}>{st.runSelftest}</Button>}>
      {report && (
        <div class="selftest">
          <Notice tone={report.ok ? 'good' : 'bad'}>{report.ok ? st.selftestPass : st.selftestFail}</Notice>
          <ul class="checks">
            {report.checks.map((c) => <li class={c.ok ? 'ok' : 'bad'}><span>{c.ok ? '✓' : '✗'}</span>{label(st.checks, c.name)}<small>{c.detail}</small></li>)}
          </ul>
          <h4 class="eyebrow">{st.timingsTitle}</h4>
          <dl class="rows compact">
            {report.timings.map((t) => <div><dt>{label(st.timings, t.name)}</dt><dd class="num">{ms(t.median_ms)} ms</dd></div>)}
          </dl>
        </div>
      )}
    </Card>
  );
}
