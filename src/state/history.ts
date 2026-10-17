/** The copies made so far, newest first. */
import { signal } from '@preact/signals';
import { api } from '../api';
import type { Session } from '../api/types';

export const sessions = signal<Session[]>([]);

export async function loadHistory(): Promise<void> {
  sessions.value = await api.getHistory();
}
