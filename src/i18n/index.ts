/**
 * Messages and formatting. One JSON file per language (src/locales); English is the fallback.
 * A message is a string with {placeholders}, or a plural object with CLDR forms
 * ({ "one": "...", "other": "..." }) chosen with Intl.PluralRules on the `count` parameter.
 */
import { computed, signal } from '@preact/signals';
import en from '../locales/en.json';
import tr from '../locales/tr.json';

export type Messages = { [key: string]: string | Messages };
type Flat = Record<string, string | Record<string, string>>;

const FILES: Record<string, Messages> = { en: en as Messages, tr: tr as Messages };
export const LANGUAGES = [
  { code: 'en', nativeName: 'English' },
  { code: 'tr', nativeName: 'Türkçe' },
];

const PLURAL_FORMS = new Set(['zero', 'one', 'two', 'few', 'many', 'other']);
function isPlural(v: unknown): v is Record<string, string> {
  return !!v && typeof v === 'object' && Object.keys(v).length > 0 && Object.keys(v).every((k) => PLURAL_FORMS.has(k)) && 'other' in (v as object);
}

function flatten(obj: Messages, prefix = '', out: Flat = {}): Flat {
  for (const [k, v] of Object.entries(obj)) {
    const key = prefix ? `${prefix}.${k}` : k;
    if (typeof v === 'string' || isPlural(v)) out[key] = v as string | Record<string, string>;
    else flatten(v, key, out);
  }
  return out;
}

const tables = new Map<string, Flat>();
function table(code: string): Flat {
  let t = tables.get(code);
  if (!t) tables.set(code, (t = flatten(FILES[code] ?? FILES.en!)));
  return t;
}

/** The first language of the system adbData has, else English. */
export function systemLanguage(): string {
  const langs = typeof navigator !== 'undefined' ? (navigator.languages ?? [navigator.language]) : [];
  for (const l of langs) {
    const base = l.split('-')[0]!.toLowerCase();
    if (FILES[base]) return base;
  }
  return 'en';
}

export const locale = signal<string>('en');

export function setLanguage(code: string): void {
  const resolved = code === 'system' ? systemLanguage() : FILES[code] ? code : 'en';
  locale.value = resolved;
  if (typeof document !== 'undefined') document.documentElement.lang = resolved;
}

export type Params = Record<string, string | number>;

function interpolate(text: string, params: Params | undefined): string {
  if (!params) return text;
  return text.replace(/\{(\w+)\}/g, (m, name: string) => {
    const v = params[name];
    if (v === undefined) return m;
    return typeof v === 'number' ? formatNumber(v) : v;
  });
}

/** Translates a key. Reading `locale.value` here makes components re-render on a language change. */
export function t(key: string, params?: Params): string {
  const msg = table(locale.value)[key] ?? table('en')[key];
  if (msg === undefined) {
    if (import.meta.env?.DEV) console.warn(`missing message: ${key}`);
    return key;
  }
  if (typeof msg === 'string') return interpolate(msg, params);
  const form = new Intl.PluralRules(locale.value).select(Number(params?.count ?? 0));
  return interpolate(msg[form] ?? msg.other ?? '', params);
}

const numberFormats = new Map<string, Intl.NumberFormat>();
export function formatNumber(n: number, opts?: Intl.NumberFormatOptions): string {
  const key = opts ? `${locale.value}|${JSON.stringify(opts)}` : locale.value;
  let f = numberFormats.get(key);
  if (!f) numberFormats.set(key, (f = new Intl.NumberFormat(locale.value, opts)));
  return f.format(n);
}

export const collator = computed(() => new Intl.Collator(locale.value, { sensitivity: 'base', numeric: true }));

/** All message keys of a language (for tests and the locale checker). */
export function keysOf(code: string): string[] {
  return Object.keys(table(code));
}
