/**
 * The backend: the Rust commands inside the app, or a simulated phone when the page runs in a
 * plain browser (`npm run dev:web`, the UI tests and the screenshots).
 */
import type { AdbTool, CopyOptions, DownloadProgress, Folder, Kind, Live, PhoneInfo, PlaceAt, Session, Settings, Status, Summary } from './types';
import { call } from './invoke';
import { mockApi } from './mock';

export interface PullRequest {
  serial: string;
  phone: string;
  base: string;
  names: string[];
  /** Null for the folder in the settings. */
  dest: string | null;
  kinds: Kind[];
  options: CopyOptions;
}

export interface PushRequest {
  serial: string;
  phone: string;
  paths: string[];
  dest: string;
  options: CopyOptions;
}

export interface Api {
  readonly simulated: boolean;
  getStatus(): Promise<Status>;
  getPhone(serial: string): Promise<PhoneInfo>;
  listFolder(serial: string, path: string): Promise<Folder>;
  getPlaces(serial: string): Promise<PlaceAt[]>;
  planPull(r: PullRequest): Promise<Summary>;
  planPush(r: PushRequest): Promise<Summary>;
  startCopy(id: string): Promise<void>;
  stopCopy(): Promise<void>;
  getCopy(): Promise<Live | null>;
  getHistory(): Promise<Session[]>;
  clearHistory(): Promise<void>;
  downloadPlatformTools(): Promise<AdbTool>;
  getSettings(): Promise<Settings>;
  setSettings(settings: Settings): Promise<Settings>;
  /** A folder on the PC; null when the person cancels. */
  pickFolder(title: string, start: string | null): Promise<string | null>;
  /** Files on the PC; empty when the person cancels. */
  pickFiles(title: string): Promise<string[]>;
  openUrl(url: string): Promise<void>;
  /** Shows a file or folder in Explorer. */
  reveal(path: string): Promise<void>;
  onDownloadProgress(callback: (p: DownloadProgress) => void): Promise<() => void>;
}

async function listen<T>(event: string, callback: (payload: T) => void): Promise<() => void> {
  const { listen } = await import('@tauri-apps/api/event');
  return listen<T>(event, (e) => callback(e.payload));
}

const tauriApi: Api = {
  simulated: false,
  getStatus: () => call('get_status'),
  getPhone: (serial) => call('get_phone', { serial }),
  listFolder: (serial, path) => call('list_folder', { serial, path }),
  getPlaces: (serial) => call('get_places', { serial }),
  planPull: (r) => call('plan_pull_copy', { ...r, utcOffsetMinutes: -new Date().getTimezoneOffset() }),
  planPush: (r) => call('plan_push_copy', { ...r }),
  startCopy: (id) => call('start_copy', { id }),
  stopCopy: () => call('stop_copy'),
  getCopy: () => call('get_copy'),
  getHistory: () => call('get_history'),
  clearHistory: () => call('clear_history'),
  downloadPlatformTools: () => call('download_platform_tools'),
  getSettings: () => call('get_settings'),
  setSettings: (settings) => call('set_settings', { settings }),
  async pickFolder(title, start) {
    const { open } = await import('@tauri-apps/plugin-dialog');
    const picked = await open({ directory: true, multiple: false, title, defaultPath: start ?? undefined });
    return typeof picked === 'string' ? picked : null;
  },
  async pickFiles(title) {
    const { open } = await import('@tauri-apps/plugin-dialog');
    const picked = await open({ directory: false, multiple: true, title });
    if (!picked) return [];
    return Array.isArray(picked) ? picked : [picked];
  },
  async openUrl(url) {
    const { openUrl } = await import('@tauri-apps/plugin-opener');
    await openUrl(url);
  },
  async reveal(path) {
    const { revealItemInDir } = await import('@tauri-apps/plugin-opener');
    await revealItemInDir(path);
  },
  onDownloadProgress: (callback) => listen('download-progress', callback),
};

export const inTauri = typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window;
export const api: Api = inTauri ? tauriApi : mockApi;
