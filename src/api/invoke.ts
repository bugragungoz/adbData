/**
 * The only module that calls Tauri's `invoke`. Errors come back as `AppError` with the stable code
 * the Rust side chose (`firewall_failed`, `protected_program`, ...), which the UI translates.
 */
import { invoke as tauriInvoke } from '@tauri-apps/api/core';

export class AppError extends Error {
  constructor(
    public readonly code: string,
    public readonly detail: string,
  ) {
    super(`${code}: ${detail}`);
  }
}

export function toAppError(e: unknown): AppError {
  if (e instanceof AppError) return e;
  if (e && typeof e === 'object' && 'code' in e) {
    const o = e as { code: unknown; detail?: unknown };
    return new AppError(String(o.code), String(o.detail ?? ''));
  }
  return new AppError('internal', e instanceof Error ? e.message : String(e));
}

/** A command with its own named arguments. */
export async function call<T>(cmd: string, args: Record<string, unknown> = {}): Promise<T> {
  try {
    return await tauriInvoke<T>(cmd, args);
  } catch (e) {
    throw toAppError(e);
  }
}
