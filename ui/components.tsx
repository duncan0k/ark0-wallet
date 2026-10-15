// Building blocks of every screen. Text is always set as text: nothing from the core is parsed as HTML,
// except the QR code's SVG, which the core makes itself from an address.
import type { ComponentChildren, JSX } from 'preact';
import { createContext } from 'preact';
import { useContext, useEffect, useRef, useState } from 'preact/hooks';
import { errorText, fill, m } from './i18n';
import { coins, group } from './format';
import { brand, Logo } from './brand';

// ---- icons: 24-unit strokes, drawn for this wallet ----

const PATHS: Record<string, JSX.Element> = {
  overview: <><rect x="3.5" y="3.5" width="7" height="7" rx="1.5" /><rect x="13.5" y="3.5" width="7" height="7" rx="1.5" /><rect x="3.5" y="13.5" width="7" height="7" rx="1.5" /><rect x="13.5" y="13.5" width="7" height="7" rx="1.5" /></>,
  send: <><path d="M7 17 17 7" /><path d="M9 7h8v8" /></>,
  receive: <><path d="M17 7 7 17" /><path d="M15 17H7V9" /></>,
  activity: <><path d="M4 7h16" /><path d="M4 12h16" /><path d="M4 17h10" /></>,
  drill: <><path d="M12 3 4.5 6v5.5c0 4.6 3.1 8 7.5 9.5 4.4-1.5 7.5-4.9 7.5-9.5V6L12 3Z" /><path d="m9 12 2 2 4-4" /></>,
  settings: <><circle cx="12" cy="12" r="3" /><path d="M19.4 15a1.6 1.6 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.6 1.6 0 0 0-1.8-.3 1.6 1.6 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.6 1.6 0 0 0-1-1.5 1.6 1.6 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.6 1.6 0 0 0 .3-1.8 1.6 1.6 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.6 1.6 0 0 0 1.5-1 1.6 1.6 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.6 1.6 0 0 0 1.8.3H9a1.6 1.6 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.6 1.6 0 0 0 1 1.5 1.6 1.6 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.6 1.6 0 0 0-.3 1.8V9a1.6 1.6 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.6 1.6 0 0 0-1.5 1Z" /></>,
  copy: <><rect x="8.5" y="8.5" width="11" height="11" rx="2" /><path d="M15.5 8.5V6a1.5 1.5 0 0 0-1.5-1.5H6A1.5 1.5 0 0 0 4.5 6v8A1.5 1.5 0 0 0 6 15.5h2.5" /></>,
  check: <path d="m5 12.5 4.5 4.5L19 7.5" />,
  lock: <><rect x="5" y="10.5" width="14" height="10" rx="2" /><path d="M8 10.5V7.5a4 4 0 0 1 8 0v3" /></>,
  refresh: <><path d="M20 11a8 8 0 0 0-14.5-4.5L4 8" /><path d="M4 4v4h4" /><path d="M4 13a8 8 0 0 0 14.5 4.5L20 16" /><path d="M20 20v-4h-4" /></>,
  external: <><path d="M14 4.5h5.5V10" /><path d="M19.5 4.5 11 13" /><path d="M18 14v4a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4" /></>,
  eye: <><path d="M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12Z" /><circle cx="12" cy="12" r="3" /></>,
  eyeOff: <><path d="M3 3l18 18" /><path d="M10.6 5.6A9.6 9.6 0 0 1 12 5.5C18 5.5 21.5 12 21.5 12a17 17 0 0 1-3 3.7M6.2 6.7C3.9 8.3 2.5 12 2.5 12S6 18.5 12 18.5c1.6 0 3-.4 4.3-1" /><path d="M9.9 10a3 3 0 0 0 4.1 4.1" /></>,
  plus: <><path d="M12 5v14" /><path d="M5 12h14" /></>,
  restore: <><path d="M4 12a8 8 0 1 0 2.4-5.7" /><path d="M4 4v4.5h4.5" /></>,
  alert: <><path d="M12 4 2.8 19.5h18.4L12 4Z" /><path d="M12 10v4" /><path d="M12 17h.01" /></>,
  info: <><circle cx="12" cy="12" r="9" /><path d="M12 11v5" /><path d="M12 8h.01" /></>,
  drop: <path d="M12 3.5s6 6.4 6 10.5a6 6 0 0 1-12 0c0-4.1 6-10.5 6-10.5Z" />,
  paste: <><rect x="6" y="4.5" width="12" height="16" rx="2" /><path d="M9 4.5V3.5h6v1" /><path d="M9 11h6" /><path d="M9 15h4" /></>,
  close: <><path d="M6 6l12 12" /><path d="M18 6 6 18" /></>,
  chevron: <path d="m9 6 6 6-6 6" />,
  leaf: <><path d="M5 19c0-8 5-13.5 14-14-.5 9-6 14-14 14Z" /><path d="M5 19 13 11" /></>,
};

export function Icon({ name, size = 18 }: { name: keyof typeof PATHS | string; size?: number }) {
  return (
    <svg class="icon" width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
      {PATHS[name]}
    </svg>
  );
}

/** The mark with the name beside it: the brand on top, what it is below. */
export function Brand({ size = 30 }: { size?: number }) {
  return (
    <div class="brand">
      <Logo size={size} />
      <div class="brand-text"><strong>{brand().brand}</strong><small>{brand().product}</small></div>
    </div>
  );
}

// ---- controls ----

type ButtonProps = {
  kind?: 'primary' | 'secondary' | 'ghost' | 'danger';
  size?: 'md' | 'lg' | 'sm';
  icon?: string;
  busy?: boolean;
  disabled?: boolean;
  type?: 'button' | 'submit';
  onClick?: () => void;
  children?: ComponentChildren;
  title?: string;
  block?: boolean;
};

export function Button({ kind = 'secondary', size = 'md', icon, busy, disabled, type = 'button', onClick, children, title, block }: ButtonProps) {
  return (
    <button type={type} class={`btn btn-${kind} btn-${size}${block ? ' btn-block' : ''}${children === undefined ? ' btn-icon' : ''}`} disabled={disabled || busy} onClick={onClick} title={title} aria-busy={busy}>
      {busy ? <Spinner /> : icon ? <Icon name={icon} size={size === 'sm' ? 15 : 17} /> : null}
      {children !== undefined && <span>{children}</span>}
    </button>
  );
}

export function Spinner() {
  return <span class="spinner" aria-hidden="true" />;
}

export function Card({ children, class: cls = '', title, actions }: { children: ComponentChildren; class?: string; title?: ComponentChildren; actions?: ComponentChildren }) {
  return (
    <section class={`card ${cls}`}>
      {(title || actions) && (
        <header class="card-head">
          {title && <h3>{title}</h3>}
          {actions && <div class="card-actions">{actions}</div>}
        </header>
      )}
      {children}
    </section>
  );
}

export function Chip({ tone = 'neutral', dot, children }: { tone?: 'neutral' | 'good' | 'warn' | 'bad' | 'accent'; dot?: boolean; children: ComponentChildren }) {
  return <span class={`chip chip-${tone}${dot ? ' chip-dot' : ''}`}>{children}</span>;
}

export function Field({ label, hint, error, children, id }: { label?: ComponentChildren; hint?: ComponentChildren; error?: string | null; children: ComponentChildren; id?: string }) {
  return (
    <div class={`field${error ? ' field-error' : ''}`}>
      {label && <label class="field-label" for={id}>{label}</label>}
      {children}
      {error ? <p class="field-msg error" role="alert">{error}</p> : hint ? <p class="field-msg">{hint}</p> : null}
    </div>
  );
}

export function PasswordInput({ value, onInput, id, autoFocus, placeholder, autocomplete = 'current-password' }: {
  value: string;
  onInput: (v: string) => void;
  id?: string;
  autoFocus?: boolean;
  placeholder?: string;
  autocomplete?: string;
}) {
  const [visible, setVisible] = useState(false);
  const ref = useRef<HTMLInputElement>(null);
  useEffect(() => {
    if (autoFocus) ref.current?.focus();
  }, []);
  return (
    <div class="input-wrap pw">
      <input ref={ref} id={id} class="input" type={visible ? 'text' : 'password'} value={value} placeholder={placeholder}
        autocomplete={autocomplete} spellcheck={false} onInput={(e) => onInput((e.target as HTMLInputElement).value)} />
      <button type="button" class="input-affix" onClick={() => setVisible(!visible)} title={visible ? m().common.hide : m().common.show}>
        <Icon name={visible ? 'eyeOff' : 'eye'} size={16} />
      </button>
    </div>
  );
}

/** A rough strength guide: length first, then the kinds of characters. */
export function passwordStrength(p: string): 0 | 1 | 2 | 3 {
  if (p.length < 8) return 0;
  const kinds = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter((r) => r.test(p)).length + (/[^\x00-\x7f]/.test(p) ? 1 : 0);
  const score = (p.length >= 12 ? 1 : 0) + (p.length >= 16 ? 1 : 0) + (kinds >= 3 ? 1 : 0);
  return score >= 2 ? 3 : score === 1 ? 2 : 1;
}

export function StrengthMeter({ password }: { password: string }) {
  const s = passwordStrength(password);
  const text = [m().password.tooShort, m().password.weak, m().password.fair, m().password.strong][s];
  return (
    <div class={`strength strength-${s}`}>
      <div class="strength-bars"><i /><i /><i /></div>
      <span>{text}</span>
    </div>
  );
}

// ---- copying, addresses ----

/**
 * Copies text. execCommand first: it is synchronous and works in every webview the app runs in, while
 * the Clipboard API is refused by some and in WebKit can stay pending; the API is the fallback.
 */
export async function copyText(text: string): Promise<boolean> {
  const area = document.createElement('textarea');
  area.value = text;
  area.readOnly = true;
  area.style.position = 'fixed';
  area.style.opacity = '0';
  document.body.appendChild(area);
  area.select();
  let ok = false;
  try {
    ok = document.execCommand('copy');
  } catch {
    ok = false;
  }
  area.remove();
  if (ok) return true;
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

export function CopyButton({ text, label, size = 'sm', kind = 'ghost' }: { text: string; label?: boolean; size?: 'sm' | 'md'; kind?: 'ghost' | 'secondary' }) {
  const [done, setDone] = useState(false);
  const toast = useToast();
  const copy = async () => {
    if (await copyText(text)) {
      setDone(true);
      toast(m().common.copied, 'good');
      setTimeout(() => setDone(false), 1600);
    } else {
      toast(errorText('internal'), 'bad');
    }
  };
  return (
    <Button kind={kind} size={size} icon={done ? 'check' : 'copy'} onClick={copy} title={m().common.copy}>
      {label ? (done ? m().common.copied : m().common.copy) : undefined}
    </Button>
  );
}

export function Mono({ children, class: cls = '', title }: { children: ComponentChildren; class?: string; title?: string }) {
  return <span class={`mono ${cls}`} title={title}>{children}</span>;
}

// ---- dialogs and toasts ----

export function Modal({ title, onClose, children, footer, wide }: { title: ComponentChildren; onClose: () => void; children: ComponentChildren; footer?: ComponentChildren; wide?: boolean }) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && onClose();
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);
  return (
    <div class="modal-backdrop" onClick={(e) => e.target === e.currentTarget && onClose()}>
      <div class={`modal${wide ? ' modal-wide' : ''}`} role="dialog" aria-modal="true">
        <header class="modal-head">
          <h2>{title}</h2>
          <button class="icon-btn" onClick={onClose} title={m().common.close}><Icon name="close" /></button>
        </header>
        <div class="modal-body">{children}</div>
        {footer && <footer class="modal-foot">{footer}</footer>}
      </div>
    </div>
  );
}

type Toast = { id: number; text: string; tone: 'good' | 'bad' | 'neutral' };
const ToastContext = createContext<(text: string, tone?: Toast['tone']) => void>(() => {});

export function ToastHost({ children }: { children: ComponentChildren }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const push = (text: string, tone: Toast['tone'] = 'neutral') => {
    const id = Date.now() + Math.random();
    setToasts((t) => [...t.slice(-2), { id, text, tone }]);
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), 2600);
  };
  return (
    <ToastContext.Provider value={push}>
      {children}
      <div class="toasts" aria-live="polite">
        {toasts.map((t) => <div key={t.id} class={`toast toast-${t.tone}`}>{t.tone === 'good' && <Icon name="check" size={16} />}{t.text}</div>)}
      </div>
    </ToastContext.Provider>
  );
}

export function useToast() {
  return useContext(ToastContext);
}

export function Notice({ tone = 'info', children }: { tone?: 'info' | 'warn' | 'bad' | 'good'; children: ComponentChildren }) {
  return (
    <div class={`notice notice-${tone}`}>
      <Icon name={tone === 'info' ? 'info' : tone === 'good' ? 'check' : 'alert'} size={17} />
      <div>{children}</div>
    </div>
  );
}

export function Amount({ sats, size = 'md' }: { sats: number; size?: 'md' | 'lg' | 'xl' }) {
  return (
    <span class={`amount amount-${size}`}>
      <span class="amount-value">{coins(sats)}</span>
      <span class="amount-unit">{m().common.unit}</span>
    </span>
  );
}

/**
 * Two bars, one per signature, to show how much room each takes in a transaction. Compact (for a side
 * panel) puts each bar under its label and gives only the signature's size.
 */
export function CompareBars({ rows, compact }: { rows: { label: string; bytes: number; vsize: number; tone: 'accent' | 'neutral' }[]; compact?: boolean }) {
  const max = Math.max(...rows.map((r) => r.vsize));
  const a = m().activity;
  return (
    <div class={`compare-rows${compact ? ' compact' : ''}`}>
      {rows.map((r) => (
        <div class="compare-row">
          <span class="compare-label">{r.label}</span>
          <span class="compare-track"><i class={`compare-fill ${r.tone}`} style={{ width: `${Math.max(2, (r.vsize / max) * 100)}%` }} /></span>
          <span class="compare-value num">
            {compact ? fill(m().send.bytes, { n: group(r.bytes) }) : `${fill(a.signatureBytes, { n: group(r.bytes) })} · ${fill(a.txVsize, { n: group(r.vsize) })}`}
          </span>
        </div>
      ))}
    </div>
  );
}

const TOKENS = /(ML-DSA-44|SLH-DSA|FIPS 204|BIP-340|AES-256-GCM)/;

/** Text in which technical names such as ML-DSA-44 never break at their hyphens. */
export function Text({ children }: { children: string }) {
  return <>{children.split(TOKENS).map((part, i) => (i % 2 ? <span class="nobr">{part}</span> : part))}</>;
}
