/**
 * A copy: the review before it starts (what will be copied, where, what is already there), then
 * its progress, read four times a second while it runs.
 */
import { signal } from '@preact/signals';
import { api, type PullRequest, type PushRequest } from '../api';
import type { CopyOptions, Live, Summary } from '../api/types';
import { errorMessage } from '../lib/errors';
import { loadHistory } from './history';
import { refreshStatus } from './device';
import { settings } from './settings';
import { page } from './ui';

export type Review =
  | { direction: 'toPc'; request: PullRequest; summary: Summary | null; error: string | null; planning: boolean }
  | { direction: 'toPhone'; request: PushRequest; summary: Summary | null; error: string | null; planning: boolean };

export const review = signal<Review | null>(null);
export const live = signal<Live | null>(null);

export function defaultOptions(): CopyOptions {
  const s = settings.value;
  return {
    existing: s?.existing ?? 'skip',
    layout: s?.layout ?? 'keep',
    keepDates: s?.keepDates ?? true,
    check: s?.check ?? false,
    hidden: s?.showHidden ?? false,
  };
}

let planRequest = 0;

/** Plans (again) what the review shows; called when it opens and when an option changes. */
export async function plan(next: Review): Promise<void> {
  const mine = ++planRequest;
  review.value = { ...next, planning: true, error: null };
  try {
    const summary = next.direction === 'toPc' ? await api.planPull(next.request) : await api.planPush(next.request);
    if (mine === planRequest && review.value) review.value = { ...review.value, summary, planning: false };
  } catch (e) {
    if (mine === planRequest && review.value) review.value = { ...review.value, summary: null, planning: false, error: errorMessage(e) };
  }
}

export function closeReview(): void {
  planRequest++;
  review.value = null;
}

let timer: ReturnType<typeof setInterval> | null = null;

async function poll(): Promise<void> {
  try {
    const l = await api.getCopy();
    live.value = l;
    if (!l || l.result) {
      stopPolling();
      if (l?.result) {
        void loadHistory();
        void refreshStatus();
      }
    }
  } catch {
    // The next read tries again.
  }
}

function startPolling(): void {
  if (timer) return;
  void poll();
  timer = setInterval(() => void poll(), 250);
}

function stopPolling(): void {
  if (timer) clearInterval(timer);
  timer = null;
}

/** Starts the reviewed copy and shows its progress. */
export async function start(): Promise<void> {
  const r = review.value;
  if (!r?.summary) return;
  await api.startCopy(r.summary.id);
  review.value = null;
  page.value = 'copy';
  startPolling();
}

export async function stop(): Promise<void> {
  await api.stopCopy();
  void poll();
}

/** Picks up a copy that was running when the window opened. */
export async function resume(): Promise<void> {
  const l = await api.getCopy();
  live.value = l;
  if (l && !l.result) startPolling();
}
