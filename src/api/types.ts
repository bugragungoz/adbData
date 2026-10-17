/** What the Rust commands send and take, field for field (camelCase). */

export type AdbSource = 'custom' | 'managed' | 'path' | 'sdk';
export interface AdbTool {
  source: AdbSource;
  path: string;
  version: string;
}

export type DeviceState = 'ready' | 'unauthorized' | 'offline' | 'noPermission' | 'otherMode';
export type Transport = 'usb' | 'wifi' | 'emulator';
export interface DeviceEntry {
  serial: string;
  state: DeviceState;
  transport: Transport;
  model: string | null;
  device: string | null;
  product: string | null;
}

export interface Status {
  adb: AdbTool | null;
  adbProblem: { code: 'missing' | 'broken'; detail: string } | null;
  devices: DeviceEntry[];
  busy: boolean;
  downloading: boolean;
}

export interface PhoneInfo {
  serial: string;
  name: string;
  android: string;
  sdk: number;
  storageTotal: number | null;
  storageFree: number | null;
  largeFiles: boolean;
}

export type Kind = 'photo' | 'video' | 'audio' | 'document' | 'archive' | 'app' | 'other';

export interface Item {
  name: string;
  dir: boolean;
  size: number;
  /** Seconds since 1970. */
  mtime: number;
  kind: Kind;
  hidden: boolean;
}

export interface Folder {
  path: string;
  items: Item[];
}

export type PlaceKey = 'storage' | 'camera' | 'screenshots' | 'pictures' | 'downloads' | 'documents' | 'whatsapp' | 'music' | 'movies' | 'recordings';
export interface PlaceAt {
  key: PlaceKey;
  path: string;
}

export type Existing = 'skip' | 'keepBoth' | 'replace';
export type Layout = 'keep' | 'byMonth';

export interface CopyOptions {
  existing: Existing;
  layout: Layout;
  keepDates: boolean;
  check: boolean;
  hidden: boolean;
}

export interface Summary {
  id: string;
  to: string;
  files: number;
  bytes: number;
  skipped: number;
  skippedBytes: number;
  filtered: number;
  renamed: number;
  numbered: number;
  replaced: number;
  unreadable: number;
  free: number | null;
}

export type Direction = 'toPc' | 'toPhone';

export interface Failure {
  path: string;
  code: 'refused' | 'local' | 'diskFull' | 'mismatch' | 'disconnected';
  detail: string;
}

export interface Session {
  id: string;
  at: number;
  direction: Direction;
  phone: string;
  from: string;
  to: string;
  planned: number;
  copied: number;
  bytes: number;
  skipped: number;
  failedCount: number;
  failed: Failure[];
  checked: number;
  checkUnavailable: boolean;
  stopped: boolean;
  disconnected: boolean;
  diskFull: boolean;
  seconds: number;
}

export interface About {
  id: string;
  serial: string;
  phone: string;
  direction: Direction;
  from: string;
  to: string;
  skipped: number;
  options: { keepDates: boolean; check: boolean };
}

export interface Live {
  about: About;
  files: number;
  bytes: number;
  index: number;
  current: string;
  done: number;
  started: number;
  checking: [number, number] | null;
  stopping: boolean;
  result: Session | null;
}

export interface Settings {
  theme: 'system' | 'dark' | 'light';
  language: string;
  adbPath: string;
  destination: string;
  existing: Existing;
  layout: Layout;
  keepDates: boolean;
  check: boolean;
  showHidden: boolean;
  /** Read only: where copies go when `destination` is empty. */
  defaultDestination: string;
}

export interface DownloadProgress {
  done: number;
  total: number | null;
}
