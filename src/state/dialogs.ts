/**
 * In-app questions that return a Promise. Never window.confirm, alert or prompt: they block the
 * window, ignore the theme and the language, and in the app's webview they do not wait for an
 * answer. `await confirm(...)` resolves only when the person answers; Escape, the scrim and Cancel
 * all answer false.
 */
import { signal } from '@preact/signals';

export interface ConfirmRequest {
  id: number;
  title: string;
  body: string;
  confirmLabel: string;
  cancelLabel: string;
  danger: boolean;
  resolve: (ok: boolean) => void;
}

export const confirmQueue = signal<ConfirmRequest[]>([]);
let next = 1;

export function confirm(opts: { title: string; body: string; confirmLabel: string; cancelLabel: string; danger?: boolean }): Promise<boolean> {
  return new Promise((resolve) => {
    const id = next++;
    const done = (ok: boolean) => {
      confirmQueue.value = confirmQueue.value.filter((c) => c.id !== id);
      resolve(ok);
    };
    confirmQueue.value = [...confirmQueue.value, { id, danger: false, ...opts, resolve: done }];
  });
}
