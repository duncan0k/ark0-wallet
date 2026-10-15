// The window: onboarding until a wallet is open, then the sidebar and the screens. The overview is
// fetched here and shared, refreshed every 30 seconds and after a send.
import { listen } from '@tauri-apps/api/event';
import { getCurrentWindow } from '@tauri-apps/api/window';
import { useCallback, useEffect, useErrorBoundary, useRef, useState } from 'preact/hooks';
import { core, type AppInfo, type Overview as OverviewData, type Settings as SettingsData, type Status } from './api';
import { Brand, Button, Icon, ToastHost } from './components';
import { brand, Logo } from './brand';
import { applyLanguage, m } from './i18n';
import { group } from './format';
import { Activity } from './screens/activity';
import { Drill } from './screens/drill';
import { CreateFlow, Frame, RestoreFlow, Unlock, Welcome } from './screens/onboarding';
import { Overview } from './screens/overview';
import { Receive } from './screens/receive';
import { Send } from './screens/send';
import { Settings } from './screens/settings';

type Screen = 'overview' | 'send' | 'receive' | 'activity' | 'drill' | 'settings';
const NAV: { id: Screen; icon: string }[] = [
  { id: 'overview', icon: 'overview' },
  { id: 'send', icon: 'send' },
  { id: 'receive', icon: 'receive' },
  { id: 'activity', icon: 'activity' },
  { id: 'drill', icon: 'drill' },
  { id: 'settings', icon: 'settings' },
];
const REFRESH_MS = 30_000;

export function App() {
  const [status, setStatus] = useState<Status | null>(null);
  const [settings, setSettings] = useState<SettingsData>({ language: 'auto', auto_lock_minutes: 15 });
  const [, setLang] = useState('');
  const [onboard, setOnboard] = useState<'welcome' | 'create' | 'restore'>('welcome');
  const [failure, setFailure] = useState<string | null>(null);
  const [renderError] = useErrorBoundary();

  const applySettings = (s: SettingsData) => {
    setSettings(s);
    setLang(applyLanguage(s.language));
    getCurrentWindow().setTitle(brand().name).catch(() => {});
  };

  useEffect(() => {
    core.settingsGet().then(applySettings).catch(() => applySettings(settings));
    core.status().then(setStatus, (err) => setFailure(describe(err)));
    const off = listen('wallet-locked', () => core.status().then(setStatus));
    return () => { off.then((f) => f()); };
  }, []);

  if (failure !== null || renderError) return <Failed detail={failure ?? describe(renderError)} />;
  if (status === null) return <div class="boot"><Logo size={48} /></div>;

  let body;
  if (status.unlocked) {
    body = <Main settings={settings} legacy={status.legacy === true} onSettings={applySettings} onStatus={setStatus} />;
  } else if (status.exists) {
    body = <Unlock onDone={setStatus} onForgotten={(s) => { setOnboard('welcome'); setStatus(s); }} />;
  } else if (onboard === 'create') {
    body = <CreateFlow onDone={setStatus} onBack={() => setOnboard('welcome')} />;
  } else if (onboard === 'restore') {
    body = <RestoreFlow onDone={setStatus} onBack={() => setOnboard('welcome')} />;
  } else {
    body = <Welcome onCreate={() => setOnboard('create')} onRestore={() => setOnboard('restore')} />;
  }
  return <ToastHost>{body}</ToastHost>;
}

function describe(err: unknown): string {
  if (err instanceof Error) return `${err.name}: ${err.message}`;
  return typeof err === 'string' ? err : JSON.stringify(err);
}

/** When the core does not answer or a screen cannot be drawn: what happened, instead of a blank window. */
function Failed({ detail }: { detail: string }) {
  const b = m().boot;
  return (
    <Frame>
      <div class="onboard-head">
        <h1>{b.title}</h1>
        <p class="lead">{b.body}</p>
      </div>
      <pre class="node-says">{detail}</pre>
      <Button kind="primary" size="lg" icon="refresh" onClick={() => location.reload()} block>{b.retry}</Button>
    </Frame>
  );
}

function Main({ settings, legacy, onSettings, onStatus }: { settings: SettingsData; legacy: boolean; onSettings: (s: SettingsData) => void; onStatus: (s: Status) => void }) {
  const [screen, setScreen] = useState<Screen>('overview');
  const [data, setData] = useState<OverviewData | null>(null);
  const [info, setInfo] = useState<AppInfo | null>(null);
  const [loading, setLoading] = useState(false);
  const [version, setVersion] = useState(0);
  const lastTouch = useRef(0);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      setData(await core.overview());
    } catch (err) {
      if ((err as { code?: string }).code === 'locked') onStatus(await core.status());
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    core.appInfo().then(setInfo);
    refresh();
    const timer = setInterval(refresh, REFRESH_MS);
    // Use of the window keeps the wallet unlocked; reported at most every 20 seconds.
    const onUse = () => {
      const now = Date.now();
      if (now - lastTouch.current > 20_000) {
        lastTouch.current = now;
        core.touch();
      }
    };
    window.addEventListener('pointerdown', onUse);
    window.addEventListener('keydown', onUse);
    return () => {
      clearInterval(timer);
      window.removeEventListener('pointerdown', onUse);
      window.removeEventListener('keydown', onUse);
    };
  }, []);

  const lock = async () => {
    await core.lock();
    onStatus(await core.status());
  };

  const chain = data?.chain;
  const title = m().nav[screen];
  return (
    <div class="shell">
      <aside class="sidebar">
        <Brand />
        <nav class="nav">
          {NAV.map((n) => (
            <button class={`nav-item${screen === n.id ? ' on' : ''}`} onClick={() => setScreen(n.id)} aria-current={screen === n.id ? 'page' : undefined}>
              <Icon name={n.icon} />
              <span>{m().nav[n.id]}</span>
            </button>
          ))}
        </nav>
        <div class="side-foot">
          <div class={`net${data?.problem ? ' net-bad' : chain ? ' net-ok' : ''}`}>
            <span class="net-dot" />
            <div>
              <strong>{m().app.network}</strong>
              <small class="muted num">{chain ? `#${group(chain.tip)}` : data?.problem ? '—' : m().common.loading}</small>
            </div>
          </div>
          <button class="lock-btn" onClick={lock} title={m().common.lock}><Icon name="lock" size={17} /><span>{m().common.lock}</span></button>
        </div>
      </aside>
      <main class="content">
        <header class="topbar">
          <h1>{title}</h1>
          <div class="topbar-actions">
            <span class="testnet-pill" title={m().app.testnet}>{m().app.testnetShort}</span>
            <Button kind="ghost" size="sm" icon="refresh" busy={loading} onClick={() => { refresh(); setVersion((v) => v + 1); }} title={m().common.refresh} />
          </div>
        </header>
        {screen === 'overview' && <Overview data={data} legacy={legacy} loading={loading} onRetry={refresh} onSend={() => setScreen('send')} onReceive={() => setScreen('receive')} />}
        {screen === 'send' && <Send data={data} info={info} onSent={() => { refresh(); setVersion((v) => v + 1); }} onActivity={() => setScreen('activity')} />}
        {screen === 'receive' && <Receive data={data} />}
        {screen === 'activity' && <Activity info={info} version={version} />}
        {screen === 'drill' && <Drill data={data} legacy={legacy} />}
        {screen === 'settings' && <Settings settings={settings} info={info} onSettings={onSettings} onRemoved={onStatus} />}
        <footer class="content-foot">{m().app.testnet}</footer>
      </main>
    </div>
  );
}
