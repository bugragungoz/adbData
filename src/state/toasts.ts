/** Snackbar stack: short confirmations with an optional action (Undo). Errors stay until closed. */
import { signal } from '@preact/signals';

export type ToastTone = 'info' | 'ok' | 'warn';

export interface Toast {
  id: number;
  message: string;
  tone: ToastTone;
  actionLabel?: string | undefined;
  onAction?: (() => void | Promise<void>) | undefined;
  /** ms; 0 keeps it until closed. */
  duration: number;
}

export const toasts = signal<Toast[]>([]);
let next = 1;

export function dismissToast(id: number): void {
  toasts.value = toasts.value.filter((t) => t.id !== id);
}

export function toast(message: string, opts: Partial<Omit<Toast, 'id' | 'message'>> = {}): number {
  const id = next++;
  const tone = opts.tone ?? 'info';
  const duration = opts.duration ?? (tone === 'warn' ? 0 : opts.actionLabel ? 8000 : 4000);
  toasts.value = [...toasts.value.slice(-3), { id, message, tone, duration, actionLabel: opts.actionLabel, onAction: opts.onAction }];
  if (duration > 0) setTimeout(() => dismissToast(id), duration);
  return id;
}
