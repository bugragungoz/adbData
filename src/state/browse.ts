/** The folder shown from the phone, what is selected in it, and the places to jump to. */
import { computed, signal } from '@preact/signals';
import { api } from '../api';
import type { Item, Kind, PlaceAt } from '../api/types';
import { errorMessage } from '../lib/errors';
import { onPhoneChange, ready } from './device';
import { settings } from './settings';

export const STORAGE = '/sdcard';

export const path = signal(STORAGE);
export const items = signal<Item[] | null>(null);
export const loading = signal(false);
export const listError = signal<string | null>(null);
export const places = signal<PlaceAt[]>([]);
export const selected = signal<Set<string>>(new Set());
/** Only these kinds of file are shown and copied; empty for all. */
export const kindFilter = signal<Kind[]>([]);

/** What the table shows: hidden names only when the settings say so, and the kind filter. */
export const visible = computed<Item[]>(() => {
  const showHidden = settings.value?.showHidden ?? false;
  const kinds = kindFilter.value;
  return (items.value ?? []).filter((i) => (showHidden || !i.hidden) && (i.dir || kinds.length === 0 || kinds.includes(i.kind)));
});

export const selectedItems = computed(() => visible.value.filter((i) => selected.value.has(i.name)));

/** The folders above the one shown, for the breadcrumb: [["sdcard", "/sdcard"], ...]. */
export const crumbs = computed<[string, string][]>(() => {
  const parts = path.value.split('/').filter(Boolean);
  return parts.map((p, i) => [p, `/${parts.slice(0, i + 1).join('/')}`]);
});

let request = 0;

export async function open(to: string): Promise<void> {
  const d = ready.value;
  if (!d) return;
  const mine = ++request;
  loading.value = true;
  listError.value = null;
  try {
    const folder = await api.listFolder(d.serial, to);
    if (mine !== request) return;
    path.value = folder.path;
    items.value = folder.items;
    selected.value = new Set();
  } catch (e) {
    if (mine === request) listError.value = errorMessage(e);
  } finally {
    if (mine === request) loading.value = false;
  }
}

export function refresh(): Promise<void> {
  return open(path.value);
}

export function up(): Promise<void> {
  const parent = path.value.replace(/\/[^/]+\/?$/, '') || '/';
  return open(parent);
}

export function toggle(name: string, on: boolean): void {
  const next = new Set(selected.value);
  if (on) next.add(name);
  else next.delete(name);
  selected.value = next;
}

export function selectAll(on: boolean): void {
  selected.value = on ? new Set(visible.value.map((i) => i.name)) : new Set();
}

export function toggleKind(kind: Kind): void {
  const now = kindFilter.value;
  kindFilter.value = now.includes(kind) ? now.filter((k) => k !== kind) : [...now, kind];
}

async function loadPlaces(serial: string): Promise<void> {
  try {
    places.value = await api.getPlaces(serial);
  } catch {
    places.value = [{ key: 'storage', path: STORAGE }];
  }
}

// A phone that appears opens at the camera folder when it has one; one that goes away clears all.
onPhoneChange((serial) => {
  request++;
  items.value = null;
  selected.value = new Set();
  listError.value = null;
  if (!serial) {
    places.value = [];
    return;
  }
  void loadPlaces(serial).then(() => {
    const camera = places.value.find((p) => p.key === 'camera');
    void open(camera?.path ?? STORAGE);
  });
});
