/**
 * The phone: adb's status every two seconds, the phone chosen and what it is. A phone that
 * appears is read at once; one that goes away is forgotten.
 */
import { computed, signal } from '@preact/signals';
import { api } from '../api';
import type { DeviceEntry, PhoneInfo, Status } from '../api/types';
import { errorMessage } from '../lib/errors';

export const status = signal<Status | null>(null);
export const statusError = signal<string | null>(null);
export const chosenSerial = signal<string | null>(null);
export const phone = signal<PhoneInfo | null>(null);

export const devices = computed<DeviceEntry[]>(() => status.value?.devices ?? []);

/** The phone in use: the one chosen, else the first one that is ready, else the first one. */
export const current = computed<DeviceEntry | null>(() => {
  const list = devices.value;
  return list.find((d) => d.serial === chosenSerial.value) ?? list.find((d) => d.state === 'ready') ?? list[0] ?? null;
});

export const ready = computed(() => (current.value?.state === 'ready' ? current.value : null));

/** The phone's name for people: what it reported, else adb's model, else its serial. */
export const phoneName = computed(() => {
  const d = current.value;
  if (!d) return '';
  if (phone.value?.serial === d.serial) return phone.value.name;
  return d.model ? d.model.replace(/_/g, ' ') : d.serial;
});

const listeners = new Set<(serial: string | null) => void>();
/** Hears when the phone in use changes (connected, unplugged, another one chosen). */
export function onPhoneChange(listener: (serial: string | null) => void): void {
  listeners.add(listener);
}

let readFor: string | null = null;

async function readPhone(serial: string): Promise<void> {
  readFor = serial;
  for (const l of listeners) l(serial);
  try {
    const info = await api.getPhone(serial);
    if (readFor === serial) phone.value = info;
  } catch {
    // The status shows what is wrong; the name falls back to adb's model.
  }
}

export async function refreshStatus(): Promise<void> {
  try {
    status.value = await api.getStatus();
    statusError.value = null;
  } catch (e) {
    statusError.value = errorMessage(e);
    return;
  }
  const d = ready.value;
  if (d && d.serial !== readFor) void readPhone(d.serial);
  if (!d && readFor) {
    readFor = null;
    phone.value = null;
    for (const l of listeners) l(null);
  }
}

export function choose(serial: string): void {
  chosenSerial.value = serial;
  void refreshStatus();
}

let timer: ReturnType<typeof setInterval> | null = null;
export function startPolling(): void {
  if (timer) return;
  void refreshStatus();
  timer = setInterval(() => void refreshStatus(), 2000);
}
