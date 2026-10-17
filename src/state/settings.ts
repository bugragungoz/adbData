/** Settings (kept by the Rust side) and the theme and language they select. */
import { computed, effect, signal } from '@preact/signals';
import { api } from '../api';
import type { Settings } from '../api/types';
import { setLanguage } from '../i18n';

export const settings = signal<Settings | null>(null);

const systemDark = signal(typeof matchMedia === 'function' ? !matchMedia('(prefers-color-scheme: light)').matches : true);
if (typeof matchMedia === 'function') {
  matchMedia('(prefers-color-scheme: light)').addEventListener?.('change', (e) => {
    systemDark.value = !e.matches;
  });
}

export const theme = computed<'dark' | 'light'>(() => {
  const t = settings.value?.theme ?? 'system';
  if (t === 'system') return systemDark.value ? 'dark' : 'light';
  return t;
});

effect(() => {
  if (typeof document !== 'undefined') document.documentElement.dataset.theme = theme.value;
});

effect(() => {
  setLanguage(settings.value?.language ?? 'system');
});

export async function loadSettings(): Promise<void> {
  settings.value = await api.getSettings();
}

/** Saves a change; the screen updates at once and settles on what the Rust side stored. */
export async function saveSettings(patch: Partial<Settings>): Promise<void> {
  const before = settings.value;
  if (!before) return;
  settings.value = { ...before, ...patch };
  try {
    settings.value = await api.setSettings({ ...before, ...patch });
  } catch (e) {
    settings.value = before;
    throw e;
  }
}
