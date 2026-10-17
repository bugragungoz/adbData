/**
 * A simulated phone for the page in a plain browser: a made-up "Example Phone 12" with a camera
 * folder, screenshots, downloads, documents and a chat app's media, copies that run at a cable's
 * speed, and a history. Everything in it is invented.
 *
 * `?fast` shortens every wait (UI tests, screenshots). `?scenario=noadb`, `nophone` and
 * `unauthorized` start in those states; `?scenario=copying` starts in the middle of a copy.
 * Pickers return `window.__adbdataPickFolder` and `window.__adbdataPickFiles` when a test set them.
 */
import type { Api, PullRequest, PushRequest } from './index';
import { AppError } from './invoke';
import type { DeviceEntry, Folder, Item, Kind, Live, PlaceAt, Session, Settings, Status, Summary } from './types';

const params = new URLSearchParams(typeof location !== 'undefined' ? location.search : '');
const FAST = params.has('fast');
const SCENARIO = params.get('scenario') ?? '';
const ms = (n: number) => (FAST ? Math.min(n, 120) : n);
const delay = <T>(value: T, wait = 120): Promise<T> => new Promise((resolve) => setTimeout(() => resolve(structuredClone(value)), ms(wait)));

const SERIAL = 'EX12A0B1C2';
const PHONE = 'Example Phone 12';
const MB = 1_000_000;

// A repeatable "random" sequence, so the screenshots are the same every time.
let seed = 7;
const rand = () => {
  seed = (seed * 1_103_515_245 + 12_345) % 2_147_483_648;
  return seed / 2_147_483_648;
};

interface Node {
  dir: boolean;
  size: number;
  mtime: number;
  children?: Map<string, Node>;
}

const dir = (entries: [string, Node][] = [], mtime = 1_727_000_000): Node => ({ dir: true, size: 3488, mtime, children: new Map(entries) });
const file = (size: number, mtime: number): Node => ({ dir: false, size: Math.round(size), mtime });
const pad = (n: number) => String(n).padStart(2, '0');

/** IMG_20240914_183012.jpg and its time. */
function stamped(prefix: string, ext: string, t: number): string {
  const d = new Date(t * 1000);
  return `${prefix}_${d.getUTCFullYear()}${pad(d.getUTCMonth() + 1)}${pad(d.getUTCDate())}_${pad(d.getUTCHours())}${pad(d.getUTCMinutes())}${pad(d.getUTCSeconds())}.${ext}`;
}

function camera(): Node {
  const entries: [string, Node][] = [];
  let t = 1_717_200_000; // June 2024
  for (let i = 0; i < 148; i++) {
    t += Math.round(20_000 + rand() * 160_000);
    if (i % 11 === 5) entries.push([stamped('VID', 'mp4', t), file(30 * MB + rand() * 380 * MB, t)]);
    else entries.push([stamped('IMG', 'jpg', t), file(2.1 * MB + rand() * 3.4 * MB, t)]);
  }
  entries.push(['.trashed-1729000000-IMG_20240601_101010.jpg', file(3.1 * MB, 1_729_000_000)]);
  return dir(entries, t);
}

function screenshots(): Node {
  const entries: [string, Node][] = [];
  let t = 1_720_000_000;
  for (let i = 0; i < 36; i++) {
    t += Math.round(40_000 + rand() * 300_000);
    entries.push([stamped('Screenshot', 'png', t), file(0.3 * MB + rand() * 1.4 * MB, t)]);
  }
  return dir(entries, t);
}

function chatMedia(): Node {
  const images: [string, Node][] = [];
  let t = 1_722_000_000;
  for (let i = 0; i < 52; i++) {
    t += Math.round(10_000 + rand() * 120_000);
    images.push([`IMG-${new Date(t * 1000).toISOString().slice(0, 10).replace(/-/g, '')}-WA${String(i).padStart(4, '0')}.jpg`, file(0.08 * MB + rand() * 0.3 * MB, t)]);
  }
  const videos: [string, Node][] = [];
  for (let i = 0; i < 7; i++) {
    t += 200_000;
    videos.push([`VID-${new Date(t * 1000).toISOString().slice(0, 10).replace(/-/g, '')}-WA${String(i).padStart(4, '0')}.mp4`, file(4 * MB + rand() * 20 * MB, t)]);
  }
  return dir([
    ['Images', dir(images, t)],
    ['Video', dir(videos, t)],
    ['Documents', dir([['Ders Programı Güz 2024.pdf', file(0.4 * MB, t)], ['Lab Föyü 3.docx', file(1.1 * MB, t)]], t)],
    ['.Statuses', dir([], t)],
  ]);
}

const root: Node = dir([
  [
    'sdcard',
    dir([
      ['Alarms', dir()],
      ['Android', dir([['media', dir([['com.example.chat', dir([['Chat', dir([['Media', chatMedia()]])]])]])]])],
      ['DCIM', dir([['Camera', camera()], ['.thumbnails', dir([['1.jpg', file(20_000, 1_725_000_000)]])]])],
      [
        'Documents',
        dir([
          ['Devre Analizi Ödev 3.pdf', file(2.4 * MB, 1_728_400_000)],
          ['Elektronik II Notlar.pdf', file(8.9 * MB, 1_727_100_000)],
          ['CV - Buğra.docx', file(0.2 * MB, 1_725_900_000)],
          ['notlar.txt', file(4_200, 1_728_900_000)],
        ]),
      ],
      [
        'Download',
        dir([
          ['STM32 Reference Manual.pdf', file(14.2 * MB, 1_726_200_000)],
          ['fatura_eylul.pdf', file(0.3 * MB, 1_727_600_000)],
          ['proje_kodlari.zip', file(46 * MB, 1_728_100_000)],
          ['Sinyaller ve Sistemler.epub', file(5.6 * MB, 1_724_800_000)],
        ]),
      ],
      ['Movies', dir()],
      ['Music', dir([['Recordings', dir([['Ders kaydı 14 Ekim.m4a', file(38 * MB, 1_728_910_000)], ['Toplantı.m4a', file(12 * MB, 1_728_500_000)]])]])],
      ['Pictures', dir([['Screenshots', screenshots()]])],
    ]),
  ],
]);

function nodeAt(path: string): Node | null {
  let node: Node | undefined = root;
  for (const part of path.split('/').filter(Boolean)) {
    node = node?.children?.get(part);
    if (!node) return null;
  }
  return node;
}

const KINDS: [Kind, RegExp][] = [
  ['photo', /\.(jpe?g|png|heic|heif|webp|gif|bmp|dng)$/i],
  ['video', /\.(mp4|mov|mkv|3gp|webm)$/i],
  ['audio', /\.(mp3|m4a|aac|ogg|opus|flac|wav|amr)$/i],
  ['document', /\.(pdf|docx?|xlsx?|pptx?|txt|epub|csv)$/i],
  ['archive', /\.(zip|rar|7z|tar|gz)$/i],
  ['app', /\.(apk|apks|xapk)$/i],
];
const kindOf = (name: string): Kind => KINDS.find(([, re]) => re.test(name))?.[0] ?? 'other';
const join = (base: string, name: string) => (base.endsWith('/') ? base + name : `${base}/${name}`);

const devices: DeviceEntry[] =
  SCENARIO === 'nophone' || SCENARIO === 'noadb'
    ? []
    : [
        {
          serial: SERIAL,
          state: SCENARIO === 'unauthorized' ? 'unauthorized' : 'ready',
          transport: 'usb',
          model: SCENARIO === 'unauthorized' ? null : 'Example_Phone_12',
          device: 'example12',
          product: 'example12',
        },
      ];

let adbMissing = SCENARIO === 'noadb';

let settings: Settings = {
  theme: 'system',
  language: 'system',
  adbPath: '',
  destination: '',
  existing: 'skip',
  layout: 'keep',
  keepDates: true,
  check: false,
  showHidden: false,
  defaultDestination: 'C:\\Users\\Bugra\\Desktop\\adbData',
};

/** What is already on the PC: an earlier copy of the first 90 camera files. */
const onPc = new Set<string>();
for (const [name] of [...(nodeAt('/sdcard/DCIM/Camera')?.children ?? new Map<string, Node>())].slice(0, 90)) onPc.add(`/sdcard/DCIM/Camera/${name}`);

interface Planned {
  summary: Summary;
  jobs: { name: string; size: number; path: string }[];
  about: Live['about'];
}
let planned: Planned | null = null;
let live: Live | null = null;
let busy = false;
let stopRequested = false;
let history: Session[] = [];

const day = 86_400_000;
const now = Date.now();
history = [
  {
    id: 'h3',
    at: now - day * 0.3,
    direction: 'toPc',
    phone: PHONE,
    from: '/sdcard/DCIM/Camera',
    to: 'C:\\Users\\Bugra\\Desktop\\adbData\\Camera',
    planned: 90,
    copied: 90,
    bytes: 1_412 * MB,
    skipped: 0,
    failedCount: 0,
    failed: [],
    checked: 0,
    checkUnavailable: false,
    stopped: false,
    disconnected: false,
    diskFull: false,
    seconds: 41.2,
  },
  {
    id: 'h2',
    at: now - day * 2.2,
    direction: 'toPhone',
    phone: PHONE,
    from: 'C:\\Users\\Bugra\\Music\\Ders kayıtları',
    to: '/sdcard/Music',
    planned: 12,
    copied: 12,
    bytes: 412 * MB,
    skipped: 3,
    failedCount: 0,
    failed: [],
    checked: 12,
    checkUnavailable: false,
    stopped: false,
    disconnected: false,
    diskFull: false,
    seconds: 14.8,
  },
  {
    id: 'h1',
    at: now - day * 5.1,
    direction: 'toPc',
    phone: PHONE,
    from: '/sdcard/Android/media/com.example.chat/Chat/Media',
    to: 'C:\\Users\\Bugra\\Desktop\\adbData\\Media',
    planned: 61,
    copied: 59,
    bytes: 151 * MB,
    skipped: 0,
    failedCount: 2,
    failed: [
      { path: '/sdcard/Android/media/com.example.chat/Chat/Media/.Statuses/a1.jpg', code: 'refused', detail: 'open failed: Permission denied' },
      { path: '/sdcard/Android/media/com.example.chat/Chat/Media/.Statuses/a2.mp4', code: 'refused', detail: 'open failed: Permission denied' },
    ],
    checked: 0,
    checkUnavailable: false,
    stopped: false,
    disconnected: false,
    diskFull: false,
    seconds: 9.6,
  },
];

function walk(base: string, name: string, hidden: boolean, out: { path: string; name: string; size: number }[], top = true) {
  const path = join(base, name);
  const node = nodeAt(path);
  if (!node) return;
  if (!top && !hidden && name.startsWith('.')) return;
  if (node.dir) for (const child of node.children?.keys() ?? []) walk(path, child, hidden, out, false);
  else out.push({ path, name, size: node.size });
}

function newId(): string {
  return Math.random().toString(16).slice(2, 12);
}

/** Runs the planned copy at about 38 MB/s (much faster with ?fast). */
function run(p: Planned) {
  busy = true;
  stopRequested = false;
  const total = p.jobs.reduce((s, j) => s + j.size, 0);
  live = { about: p.about, files: p.jobs.length, bytes: total, index: 0, current: p.jobs[0]?.name ?? '', done: 0, started: Date.now(), checking: null, stopping: false, result: null };
  const speed = FAST ? 4_000 * MB : 38 * MB; // bytes per second
  const tick = 100;
  let index = 0;
  let inFile = 0;
  let done = 0;
  const timer = setInterval(() => {
    const l = live!;
    let budget = (speed * tick) / 1000;
    while (budget > 0 && index < p.jobs.length && !stopRequested) {
      const job = p.jobs[index]!;
      const take = Math.min(budget, job.size - inFile);
      inFile += take;
      done += take;
      budget -= take;
      if (inFile >= job.size) {
        index++;
        inFile = 0;
        if (p.about.direction === 'toPc') onPc.add(job.path);
      }
    }
    l.index = Math.min(index, p.jobs.length - 1);
    l.current = p.jobs[l.index]?.name ?? '';
    l.done = Math.round(done);
    if (index >= p.jobs.length || stopRequested) {
      clearInterval(timer);
      const session: Session = {
        id: p.about.id,
        at: Date.now(),
        direction: p.about.direction,
        phone: p.about.phone,
        from: p.about.from,
        to: p.about.to,
        planned: p.jobs.length,
        copied: index,
        bytes: p.jobs.slice(0, index).reduce((s, j) => s + j.size, 0),
        skipped: p.about.skipped,
        failedCount: 0,
        failed: [],
        checked: p.about.options.check ? index : 0,
        checkUnavailable: false,
        stopped: stopRequested,
        disconnected: false,
        diskFull: false,
        seconds: (Date.now() - l.started) / 1000,
      };
      l.done = session.bytes;
      l.result = session;
      history = [session, ...history];
      busy = false;
    }
  }, tick);
}

function summary(id: string, to: string, jobs: { size: number }[], skipped: { size: number }[], filtered: number, free: number | null): Summary {
  return {
    id,
    to,
    files: jobs.length,
    bytes: jobs.reduce((s, j) => s + j.size, 0),
    skipped: skipped.length,
    skippedBytes: skipped.reduce((s, j) => s + j.size, 0),
    filtered,
    renamed: 0,
    numbered: 0,
    replaced: 0,
    unreadable: 0,
    free,
  };
}

const PLACES: [PlaceAt['key'], string][] = [
  ['storage', '/sdcard'],
  ['camera', '/sdcard/DCIM/Camera'],
  ['screenshots', '/sdcard/Pictures/Screenshots'],
  ['pictures', '/sdcard/Pictures'],
  ['downloads', '/sdcard/Download'],
  ['documents', '/sdcard/Documents'],
  ['music', '/sdcard/Music'],
  ['movies', '/sdcard/Movies'],
  ['recordings', '/sdcard/Music/Recordings'],
];

function requireReady(serial: string) {
  if (adbMissing) throw new AppError('no_adb', '');
  const d = devices.find((x) => x.serial === serial);
  if (!d) throw new AppError('phone_refused', `device '${serial}' not found`);
  if (d.state !== 'ready') throw new AppError('phone_refused', `device ${d.state}`);
}

if (SCENARIO === 'copying') {
  const jobs: { name: string; size: number; path: string }[] = [];
  walk('/sdcard/DCIM', 'Camera', false, jobs);
  const rest = jobs.filter((j) => !onPc.has(j.path));
  const about = {
    id: 'running',
    serial: SERIAL,
    phone: PHONE,
    direction: 'toPc' as const,
    from: '/sdcard/DCIM/Camera',
    to: `${settings.defaultDestination}\\Camera`,
    skipped: jobs.length - rest.length,
    options: { keepDates: true, check: false },
  };
  const total = rest.reduce((s, j) => s + j.size, 0);
  live = { about, files: rest.length, bytes: total, index: 23, current: rest[23]?.name ?? '', done: Math.round(total * 0.42), started: Date.now() - 31_000, checking: null, stopping: false, result: null };
  busy = true;
}

export const mockApi: Api = {
  simulated: true,
  async getStatus(): Promise<Status> {
    return delay(
      {
        adb: adbMissing ? null : { source: 'managed' as const, path: 'C:\\Users\\Bugra\\AppData\\Local\\com.bugragungoz.adbdata\\platform-tools\\adb.exe', version: '36.0.0' },
        adbProblem: adbMissing ? { code: 'missing' as const, detail: '' } : null,
        devices: adbMissing ? [] : devices,
        busy,
        downloading: false,
      },
      40,
    );
  },
  async getPhone(serial) {
    requireReady(serial);
    return delay({ serial, name: PHONE, android: '14', sdk: 34, storageTotal: 128 * 1000 * MB, storageFree: 41.3 * 1000 * MB, largeFiles: true }, 80);
  },
  async listFolder(serial, path): Promise<Folder> {
    requireReady(serial);
    const node = nodeAt(path);
    if (!node?.dir) return delay({ path, items: [] }, 80);
    const items: Item[] = [...(node.children ?? new Map<string, Node>())].map(([name, n]) => ({
      name,
      dir: n.dir,
      size: n.size,
      mtime: n.mtime,
      kind: n.dir ? 'other' : kindOf(name),
      hidden: name.startsWith('.'),
    }));
    items.sort((a, b) => Number(b.dir) - Number(a.dir) || a.name.toLowerCase().localeCompare(b.name.toLowerCase()));
    return delay({ path, items }, 90);
  },
  async getPlaces(serial) {
    requireReady(serial);
    // The made-up chat app is not one of the known places, so it is reached by browsing.
    const found: PlaceAt[] = PLACES.filter(([, p]) => nodeAt(p)?.dir).map(([key, path]) => ({ key, path }));
    return delay(found, 60);
  },
  async planPull(r: PullRequest) {
    requireReady(r.serial);
    const all: { path: string; name: string; size: number }[] = [];
    for (const name of r.names) walk(r.base, name, r.options.hidden, all);
    const kinded = r.kinds.length ? all.filter((j) => r.kinds.includes(kindOf(j.name))) : all;
    const skipped = r.options.existing === 'skip' ? kinded.filter((j) => onPc.has(j.path)) : [];
    const jobs = kinded.filter((j) => !skipped.includes(j));
    const to = r.dest ?? (settings.destination || settings.defaultDestination);
    const id = newId();
    planned = {
      summary: summary(id, to, jobs, skipped, all.length - kinded.length, 212 * 1000 * MB),
      jobs,
      about: {
        id,
        serial: r.serial,
        phone: PHONE,
        direction: 'toPc',
        from: r.names.length === 1 ? join(r.base, r.names[0]!) : r.base,
        to,
        skipped: skipped.length,
        options: { keepDates: r.options.keepDates, check: r.options.check },
      },
    };
    return delay(planned.summary, 300);
  },
  async planPush(r: PushRequest) {
    requireReady(r.serial);
    const jobs = r.paths.map((p, i) => {
      const name = p.split(/[\\/]/).pop() ?? p;
      return { name, size: (3 + i * 2.7) * MB, path: join(r.dest, name) };
    });
    const id = newId();
    planned = {
      summary: summary(id, r.dest, jobs, [], 0, 41.3 * 1000 * MB),
      jobs,
      about: {
        id,
        serial: r.serial,
        phone: PHONE,
        direction: 'toPhone',
        from: r.paths.length === 1 ? r.paths[0]! : (r.paths[0] ?? '').replace(/[\\/][^\\/]*$/, ''),
        to: r.dest,
        skipped: 0,
        options: { keepDates: true, check: r.options.check },
      },
    };
    return delay(planned.summary, 200);
  },
  async startCopy(id) {
    if (!planned || planned.summary.id !== id) throw new AppError('plan_gone', '');
    if (busy) throw new AppError('busy', '');
    const p = planned;
    planned = null;
    if (p.about.direction === 'toPhone') {
      const folder = nodeAt(p.about.to);
      for (const j of p.jobs) folder?.children?.set(j.name, file(j.size, Math.round(Date.now() / 1000)));
    }
    run(p);
    await delay(null, 30);
  },
  async stopCopy() {
    stopRequested = true;
    if (live) live.stopping = true;
    if (SCENARIO === 'copying' && live && !live.result) {
      busy = false;
      live.result = { id: 'running', at: Date.now(), direction: 'toPc', phone: PHONE, from: live.about.from, to: live.about.to, planned: live.files, copied: live.index, bytes: live.done, skipped: live.about.skipped, failedCount: 0, failed: [], checked: 0, checkUnavailable: false, stopped: true, disconnected: false, diskFull: false, seconds: 31 };
    }
    await delay(null, 30);
  },
  getCopy: () => delay(live, 20),
  getHistory: () => delay(history, 60),
  async clearHistory() {
    history = [];
    await delay(null, 60);
  },
  async downloadPlatformTools() {
    adbMissing = false;
    if (devices.length === 0 && SCENARIO === 'noadb') {
      devices.push({ serial: SERIAL, state: 'ready', transport: 'usb', model: 'Example_Phone_12', device: 'example12', product: 'example12' });
    }
    return delay({ source: 'managed' as const, path: 'adb.exe', version: '36.0.0' }, 600);
  },
  getSettings: () => delay(settings, 40),
  async setSettings(s) {
    settings = { ...s, defaultDestination: settings.defaultDestination };
    return delay(settings, 60);
  },
  async pickFolder() {
    const w = window as unknown as { __adbdataPickFolder?: string | null };
    return delay(w.__adbdataPickFolder === undefined ? 'D:\\Telefon Yedek' : w.__adbdataPickFolder, 60);
  },
  async pickFiles() {
    const w = window as unknown as { __adbdataPickFiles?: string[] };
    return delay(w.__adbdataPickFiles ?? ['C:\\Users\\Bugra\\Music\\Ders 1.m4a', 'C:\\Users\\Bugra\\Music\\Ders 2.m4a'], 60);
  },
  async openUrl(url) {
    window.open(url, '_blank', 'noopener');
  },
  async reveal() {},
  async onDownloadProgress(callback) {
    let done = 0;
    const total = 7 * MB;
    const timer = setInterval(() => {
      done = Math.min(total, done + 1.6 * MB);
      callback({ done, total });
      if (done >= total) clearInterval(timer);
    }, ms(120));
    return () => clearInterval(timer);
  },
};
