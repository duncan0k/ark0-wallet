import { h } from 'preact';
import { locale, type Locale } from './i18n';

type Brand = { name: string; brand: string; product: string };

const ENGLISH: Brand = { name: 'Ark-0 Wallet', brand: 'Ark-0', product: 'Wallet' };

export const brands: Record<Locale, Brand> = {
  'zh-Hans': { name: '方舟 0 号钱包', brand: '方舟 0 号', product: '钱包' },
  'zh-Hant': { name: '方舟 0 號錢包', brand: '方舟 0 號', product: '錢包' },
  en: ENGLISH,
  ja: ENGLISH,
  ko: ENGLISH,
  ru: ENGLISH,
  es: ENGLISH,
};

export function brand(): Brand {
  return brands[locale()];
}

export function Logo({ size = 32 }: { size?: number }) {
  return h('svg', { class: 'logo', width: size, height: size, viewBox: '0 0 256 256', 'aria-hidden': 'true' },
    h('rect', { width: 256, height: 256, rx: 52, fill: '#03070D' }),
    h('g', { transform: 'translate(17.92 17.92) scale(0.86)' },
      h('ellipse', { cx: 128, cy: 76, rx: 38, ry: 55, fill: 'none', stroke: '#21E6FF', 'stroke-width': 26 }),
      h('path', { d: 'M12 132Q36 148 66 148H190Q220 148 244 132L210 194Q205 204 193 204H63Q51 204 46 194Z', fill: '#FFFFFF' }),
      h('path', { d: 'M16 234Q44 218 72 234T128 234T184 234T240 234', fill: 'none', stroke: '#287DFF', 'stroke-width': 14, 'stroke-linecap': 'round' }),
    ),
  );
}
