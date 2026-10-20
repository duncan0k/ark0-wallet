// Numbers and addresses as the interface shows them.
import { fill, locale, m } from './i18n';

const COIN = 100_000_000;

/** Coins from satoshis, with no trailing zeros: 150000000 is "1.5". */
export function coins(sats: number): string {
  const whole = Math.floor(sats / COIN);
  const fraction = String(sats % COIN).padStart(8, '0').replace(/0+$/, '');
  return fraction ? `${group(whole)}.${fraction}` : group(whole);
}

/**
 * A whole number with its thousands set apart, as the Ark-0 web wallet writes them: with a comma, or in
 * Russian and Spanish, where a comma marks decimals, with a no-break space from five digits on: 2,420 and
 * 12,345, or 2420 and 12 345.
 */
export function group(n: number): string {
  const text = Number.isInteger(n) ? BigInt(n).toString() : n.toString();
  const parts = /^(-?)(\d+)(.*)$/.exec(text);
  if (!parts) return text;
  const [, sign = '', whole = '', rest = ''] = parts;
  const spaced = locale() === 'ru' || locale() === 'es';
  if (spaced && whole.length < 5) return text;
  return sign + whole.replace(/\B(?=(\d{3})+$)/g, spaced ? '\u00a0' : ',') + rest;
}

/** The start and the end of a long string, for one line: tb1zabcd…wxyz. */
export function shorten(text: string, head = 10, tail = 8): string {
  return text.length <= head + tail + 1 ? text : `${text.slice(0, head)}…${text.slice(-tail)}`;
}

/** An address in groups of four, easier to compare by eye. */
export function grouped(address: string): string {
  return address.replace(/(.{4})/g, '$1 ').trim();
}

export function ago(seconds: number): string {
  const s = Math.max(0, Math.floor(Date.now() / 1000) - seconds);
  if (s < 60) return m().common.justNow;
  if (s < 3600) return fill(m().common.minutesAgo, { n: Math.floor(s / 60) });
  return new Date(seconds * 1000).toLocaleString();
}

/** Milliseconds with two significant decimals at most: 0.41, 12.3. */
export function ms(value: number): string {
  return value < 10 ? value.toFixed(2) : value < 100 ? value.toFixed(1) : value.toFixed(0);
}
