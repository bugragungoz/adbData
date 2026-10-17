/**
 * The phone: getting adb and a phone ready, then its folders, to copy from and to send files to.
 */
import { useState } from 'preact/hooks';
import { api } from '../api';
import type { DeviceEntry, Item, Kind, PlaceKey } from '../api/types';
import { t } from '../i18n';
import { errorMessage } from '../lib/errors';
import { formatBytes, formatFileDate } from '../lib/format';
import { crumbs, items, kindFilter, listError, loading, open, path, places, refresh, selectAll, selected, selectedItems, toggle, toggleKind, up, visible } from '../state/browse';
import { defaultOptions, plan } from '../state/copy';
import { current, phone, phoneName, ready, refreshStatus, status } from '../state/device';
import { toast } from '../state/toasts';
import { page } from '../state/ui';
import { Button } from '../components/Button';
import { Chip } from '../components/Chip';
import { Icon } from '../components/Icon';
import { IconButton } from '../components/IconButton';
import { EmptyState, Meter, Note, PageHeader } from '../components/Misc';
import { Checkbox } from '../components/Switch';

const TERMS_URL = 'https://developer.android.com/studio/releases/platform-tools';

const PLACE_ICONS: Record<PlaceKey, string> = {
  storage: 'home',
  camera: 'camera',
  screenshots: 'screenshot',
  pictures: 'photo',
  downloads: 'download',
  documents: 'document',
  whatsapp: 'chat',
  music: 'audio',
  movies: 'video',
  recordings: 'mic',
};

const KIND_ICONS: Record<Kind, string> = {
  photo: 'photo',
  video: 'video',
  audio: 'audio',
  document: 'document',
  archive: 'archive',
  app: 'package',
  other: 'file',
};

const FILTERS: Kind[] = ['photo', 'video', 'audio', 'document'];

function GetAdb() {
  const [progress, setProgress] = useState<{ done: number; total: number | null } | null>(null);
  const [busy, setBusy] = useState(false);
  const download = async () => {
    setBusy(true);
    setProgress({ done: 0, total: null });
    const off = await api.onDownloadProgress(setProgress);
    try {
      const tool = await api.downloadPlatformTools();
      toast(t('phone.adbReady', { version: tool.version }), { tone: 'ok' });
      await refreshStatus();
    } catch (e) {
      toast(errorMessage(e), { tone: 'warn' });
    } finally {
      off();
      setBusy(false);
      setProgress(null);
    }
  };
  const broken = status.value?.adbProblem?.code === 'broken';
  return (
    <section class="card">
      <h2 class="card-title">{t(broken ? 'phone.adbBrokenTitle' : 'phone.adbMissingTitle')}</h2>
      <p class="card-text">{broken ? t('phone.adbBrokenBody', { detail: status.value?.adbProblem?.detail ?? '' }) : t('phone.adbMissingBody')}</p>
      {progress ? (
        <div class="progress-line">
          <Meter value={progress.total ? progress.done / progress.total : 0} label={t('phone.downloading')} />
          <span>
            {progress.total ? t('phone.downloadedOf', { done: formatBytes(progress.done), total: formatBytes(progress.total) }) : t('phone.downloading')}
          </span>
        </div>
      ) : null}
      <div class="actions">
        <Button variant="primary" icon="download" onClick={() => void download()} disabled={busy}>
          {t('phone.download')}
        </Button>
        <Button variant="quiet" icon="settings" onClick={() => (page.value = 'settings')}>
          {t('phone.haveAdb')}
        </Button>
      </div>
      <p class="setting-meta">
        {t('phone.terms')}{' '}
        <button type="button" class="link-button" onClick={() => void api.openUrl(TERMS_URL)}>
          {t('phone.termsLink')}
        </button>
      </p>
    </section>
  );
}

function ConnectSteps() {
  return (
    <section class="card">
      <h2 class="card-title">{t('phone.connectTitle')}</h2>
      <ol class="steps">
        <li>{t('phone.step1')}</li>
        <li>{t('phone.step2')}</li>
        <li>{t('phone.step3')}</li>
        <li>{t('phone.step4')}</li>
      </ol>
      <p class="setting-meta">{t('phone.cableHint')}</p>
    </section>
  );
}

function StateNote({ d }: { d: DeviceEntry }) {
  const key = d.state === 'unauthorized' ? 'unauthorized' : d.state === 'offline' ? 'offline' : d.state === 'noPermission' ? 'noPermission' : 'otherMode';
  return (
    <Note icon={key === 'unauthorized' ? 'phone' : 'alert'} tone="warn" title={t(`phone.${key}Title`)}>
      {t(`phone.${key}Body`)}
    </Note>
  );
}

function Setup() {
  const st = status.value;
  const d = current.value;
  return (
    <div class="view-body">
      <PageHeader title={t('phone.setupTitle')} subtitle={t('phone.setupSubtitle')} />
      {!st ? <p class="muted">{t('status.starting')}</p> : null}
      {st && !st.adb ? <GetAdb /> : null}
      {st?.adb && d ? <StateNote d={d} /> : null}
      {st?.adb ? <ConnectSteps /> : null}
    </div>
  );
}

function Places() {
  if (places.value.length === 0) return null;
  return (
    <nav class="chip-row" aria-label={t('browse.places')}>
      {places.value.map((p) => (
        <Chip key={p.key} selected={path.value === p.path} onClick={() => void open(p.path)}>
          <Icon name={PLACE_ICONS[p.key]} size={15} />
          {t(`places.${p.key}`)}
        </Chip>
      ))}
    </nav>
  );
}

function Crumbs() {
  const list = crumbs.value;
  return (
    <nav class="crumbs" aria-label={t('browse.where')}>
      <IconButton icon="up" label={t('browse.up')} size="sm" disabled={list.length <= 1} onClick={() => void up()} />
      <ol class="crumb-list">
        {list.map(([name, to], i) => (
          <li key={to}>
            {i > 0 ? <Icon name="chevronRight" size={13} class="muted" /> : null}
            {i === list.length - 1 ? (
              <span class="crumb-here" aria-current="location">
                {name}
              </span>
            ) : (
              <button type="button" class="link-button crumb" onClick={() => void open(to)}>
                {name}
              </button>
            )}
          </li>
        ))}
      </ol>
    </nav>
  );
}

function Row({ item }: { item: Item }) {
  const on = selected.value.has(item.name);
  const enter = () => void open(`${path.value.replace(/\/$/, '')}/${item.name}`);
  return (
    <div
      class={`tr ${on ? 'is-open' : ''}`}
      role="row"
      aria-selected={on}
      onClick={(e) => {
        if ((e.target as HTMLElement).closest('button, input')) return;
        if (item.dir) enter();
        else toggle(item.name, !on);
      }}
    >
      <div class="td" role="cell">
        <Checkbox checked={on} onChange={(v) => toggle(item.name, v)} label={t('browse.select', { name: item.name })} hideLabel />
      </div>
      <div class="td" role="cell">
        <Icon name={item.dir ? 'folder' : KIND_ICONS[item.kind]} size={18} class={item.dir ? 'accent-ink' : 'muted'} />
        {item.dir ? (
          <button type="button" class="link-button name-button truncate" onClick={enter}>
            {item.name}
          </button>
        ) : (
          <span class="truncate">{item.name}</span>
        )}
      </div>
      <div class="td muted num is-extra" role="cell">
        {formatFileDate(item.mtime)}
      </div>
      <div class="td muted num cell-size" role="cell">
        {item.dir ? '' : formatBytes(item.size)}
      </div>
    </div>
  );
}

function Table() {
  const rows = visible.value;
  const allOn = rows.length > 0 && rows.every((r) => selected.value.has(r.name));
  const someOn = rows.some((r) => selected.value.has(r.name));
  if (listError.value) {
    return (
      <div class="view-body">
        <Note icon="alert" tone="warn" title={t('browse.listFailed')}>
          {listError.value}
        </Note>
      </div>
    );
  }
  if (items.value === null) return <p class="view-body muted">{t('browse.loading')}</p>;
  if (rows.length === 0) {
    return <EmptyState icon="folder" title={kindFilter.value.length ? t('browse.emptyFiltered') : t('browse.empty')} />;
  }
  return (
    <div class="table file-table" role="table" aria-label={t('browse.tableLabel', { folder: path.value })} aria-busy={loading.value}>
      <div class="thead" role="row">
        <div class="th" role="columnheader">
          <Checkbox checked={allOn} indeterminate={someOn && !allOn} onChange={(v) => selectAll(v)} label={t('browse.selectAll')} hideLabel />
        </div>
        <div class="th" role="columnheader">
          {t('browse.name')}
        </div>
        <div class="th is-extra" role="columnheader">
          {t('browse.modified')}
        </div>
        <div class="th cell-size" role="columnheader">
          {t('browse.size')}
        </div>
      </div>
      {rows.map((item) => (
        <Row key={item.name} item={item} />
      ))}
    </div>
  );
}

function copyToPc(names: string[]) {
  const d = ready.value;
  if (!d || names.length === 0) return;
  void plan({
    direction: 'toPc',
    request: { serial: d.serial, phone: phoneName.value, base: path.value, names, dest: null, kinds: kindFilter.value, options: defaultOptions() },
    summary: null,
    error: null,
    planning: true,
  });
}

async function sendHere(folder: boolean) {
  const d = ready.value;
  if (!d) return;
  let paths: string[];
  if (folder) {
    const picked = await api.pickFolder(t('send.pickFolder'), null);
    paths = picked ? [picked] : [];
  } else {
    paths = await api.pickFiles(t('send.pickFiles'));
  }
  if (paths.length === 0) return;
  void plan({
    direction: 'toPhone',
    request: { serial: d.serial, phone: phoneName.value, paths, dest: path.value, options: defaultOptions() },
    summary: null,
    error: null,
    planning: true,
  });
}

function SelectionBar() {
  const chosen = selectedItems.value;
  const busy = status.value?.busy ?? false;
  if (chosen.length === 0) {
    const all = visible.value;
    return (
      <div class="selection-bar" role="region" aria-label={t('browse.actionsLabel')}>
        <span class="muted">{t('browse.hint')}</span>
        <span class="grow" />
        <Button size="sm" icon="toPc" disabled={busy || all.length === 0} onClick={() => copyToPc(all.map((i) => i.name))}>
          {t('browse.copyFolder')}
        </Button>
      </div>
    );
  }
  const files = chosen.filter((i) => !i.dir);
  const folders = chosen.length - files.length;
  const bytes = files.reduce((s, i) => s + i.size, 0);
  return (
    <div class="selection-bar" role="region" aria-label={t('browse.actionsLabel')}>
      <strong>{t('browse.selected', { count: chosen.length })}</strong>
      <span class="muted">
        {folders ? t('browse.selectedFolders', { count: folders }) : null}
        {folders && files.length ? ' · ' : null}
        {files.length ? formatBytes(bytes) : null}
      </span>
      <span class="grow" />
      <Button size="sm" variant="quiet" onClick={() => selectAll(false)}>
        {t('browse.clear')}
      </Button>
      <Button size="sm" variant="primary" icon="toPc" disabled={busy} onClick={() => copyToPc(chosen.map((i) => i.name))}>
        {t('browse.copyToPc')}
      </Button>
    </div>
  );
}

function Browser() {
  const info = phone.value;
  const free = info?.storageFree;
  const subtitle = [
    info?.android ? t('phone.android', { version: info.android }) : null,
    free != null && info?.storageTotal ? t('phone.storage', { free: formatBytes(free), total: formatBytes(info.storageTotal) }) : null,
  ]
    .filter(Boolean)
    .join(' · ');
  const busy = status.value?.busy ?? false;
  return (
    <div class="view">
      <div class="view-head">
        <PageHeader title={phoneName.value} subtitle={subtitle}>
          <Button icon="toPhone" disabled={busy} onClick={() => void sendHere(false)}>
            {t('send.files')}
          </Button>
          <Button variant="quiet" icon="folder" disabled={busy} onClick={() => void sendHere(true)}>
            {t('send.folder')}
          </Button>
        </PageHeader>
        <Places />
        <div class="toolbar">
          <Crumbs />
          <span class="grow" />
          <div class="chip-row" role="group" aria-label={t('browse.kinds')}>
            {FILTERS.map((k) => (
              <Chip key={k} selected={kindFilter.value.includes(k)} onClick={() => toggleKind(k)}>
                {t(`kinds.${k}`)}
              </Chip>
            ))}
          </div>
          <span class="toolbar-count muted num">{t('browse.count', { count: visible.value.length })}</span>
          <IconButton icon="refresh" label={t('browse.refresh')} size="sm" onClick={() => void refresh()} />
        </div>
      </div>
      <div class="table-wrap">
        <Table />
      </div>
      <SelectionBar />
    </div>
  );
}

export function Phone() {
  return ready.value ? <Browser /> : <Setup />;
}
