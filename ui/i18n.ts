// The interface's languages: simplified and traditional Chinese, English, Japanese, Korean, Russian and
// Spanish. "auto" follows the system: zh-TW, zh-HK, zh-MO and zh-Hant read traditional, any other Chinese
// simplified, the other languages by their tag, and anything else simplified Chinese.
// The app re-renders from its root when the language changes, so m() is read fresh everywhere.
import { en, type Messages } from './messages/en';
import { es } from './messages/es';
import { ja } from './messages/ja';
import { ko } from './messages/ko';
import { ru } from './messages/ru';
import { zhHans } from './messages/zh-Hans';
import { zhHant } from './messages/zh-Hant';

export type Locale = 'zh-Hans' | 'zh-Hant' | 'en' | 'ja' | 'ko' | 'ru' | 'es';
export type LanguageSetting = Locale | 'auto';

const MESSAGES: Record<Locale, Messages> = { 'zh-Hans': zhHans, 'zh-Hant': zhHant, en, ja, ko, ru, es };

export function systemLocale(): Locale {
  for (const tag of navigator.languages ?? [navigator.language]) {
    const t = tag.toLowerCase();
    if (/^zh-(tw|hk|mo)\b|^zh-hant\b/.test(t)) return 'zh-Hant';
    if (t.startsWith('zh')) return 'zh-Hans';
    if (t.startsWith('en')) return 'en';
    if (t.startsWith('ja')) return 'ja';
    if (t.startsWith('ko')) return 'ko';
    if (t.startsWith('ru')) return 'ru';
    if (t.startsWith('es')) return 'es';
  }
  return 'zh-Hans';
}

let current: Locale = systemLocale();

export function applyLanguage(setting: LanguageSetting): Locale {
  current = setting === 'auto' ? systemLocale() : setting;
  document.documentElement.lang = current;
  return current;
}

export function locale(): Locale {
  return current;
}

/** The messages of the current language. */
export function m(): Messages {
  return MESSAGES[current];
}

/** A message with its {placeholders} filled in. */
export function fill(text: string, values: Record<string, string | number>): string {
  return text.replace(/\{(\w+)\}/g, (_, k: string) => String(values[k] ?? `{${k}}`));
}

/** The text of an error code the core returned. */
export function errorText(code: string): string {
  const errors = m().errors as Record<string, string>;
  return errors[code] ?? errors['internal'] ?? code;
}
