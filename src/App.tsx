import { useEffect } from 'preact/hooks';
import { api } from './api';
import { formatNumber, t } from './i18n';
import { formatBytes } from './lib/format';
import { live, resume } from './state/copy';
import { choose, current, devices, phoneName, startPolling, status, statusError } from './state/device';
import { loadHistory, sessions } from './state/history';
import { loadSettings } from './state/settings';
import { page, type Page } from './state/ui';
import { ConfirmHost } from './components/ConfirmHost';
import { Icon } from './components/Icon';
import { Snackbars } from './components/Snackbars';
import { Copy } from './pages/Copy';
import { History } from './pages/History';
import { Phone } from './pages/Phone';
import { ReviewDialog } from './pages/Review';
import { REPO_URL, Settings } from './pages/Settings';

const NAV: { page: Page; icon: string; count?: () => number }[] = [
  { page: 'phone', icon: 'phone' },
  { page: 'copy', icon: 'toPc' },
  { page: 'history', icon: 'history', count: () => sessions.value.length },
  { page: 'settings', icon: 'settings' },
];

/** The wordmark's mark: a phone with a down arrow, in the accent ink. */
function Mark() {
  return (
    <svg class="wordmark-mark" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
      <path d="M13.5 21.5H7A2.5 2.5 0 0 1 4.5 19V5A2.5 2.5 0 0 1 7 2.5h7A2.5 2.5 0 0 1 16.5 5v6" />
      <path d="M8.5 18.5h2" />
      <circle cx="18" cy="17.5" r="4" />
      <path d="M18 15.4v4.2M16.3 18l1.7 1.7 1.7-1.7" />
    </svg>
  );
}

function SidebarPhone() {
  const d = current.value;
  if (!d) return null;
  const others = devices.value.filter((x) => x.serial !== d.serial);
  return (
    <div class="sidebar-phone">
      <strong class="truncate">{phoneName.value}</strong>
      <span class="row">
        <Icon name={d.transport === 'wifi' ? 'wifi' : 'usb'} size={13} />
        {t(`phone.state.${d.state}`)}
      </span>
      {others.map((o) => (
        <button key={o.serial} type="button" class="link-button" onClick={() => choose(o.serial)}>
          {t('phone.switchTo', { name: o.model ? o.model.replace(/_/g, ' ') : o.serial })}
        </button>
      ))}
    </div>
  );
}

function StatusBar() {
  const s = status.value;
  const d = current.value;
  const l = live.value;
  let adb: { icon: string; text: string; tone?: string };
  if (statusError.value) adb = { icon: 'alert', text: statusError.value, tone: 'tone-warn' };
  else if (!s) adb = { icon: 'info', text: t('status.starting') };
  else if (!s.adb) adb = { icon: 'alert', text: t('status.noAdb'), tone: 'tone-warn' };
  else adb = { icon: 'checkCircle', text: t('status.adb', { version: s.adb.version }), tone: 'tone-ok' };
  const running = l && !l.result;
  return (
    <footer class="statusbar">
      <span class={`status-item ${adb.tone ?? ''}`}>
        <Icon name={adb.icon} size={14} />
        {adb.text}
      </span>
      {s?.adb ? (
        <>
          <span class="sep" />
          <span class={`status-item ${d?.state === 'ready' ? 'tone-ok' : ''}`}>
            <Icon name={d?.transport === 'wifi' ? 'wifi' : 'phone'} size={14} />
            {d ? `${phoneName.value} - ${t(`phone.state.${d.state}`)}` : t('status.noPhone')}
          </span>
        </>
      ) : null}
      {api.simulated ? (
        <>
          <span class="sep" />
          <span class="status-item" title={t('status.demoHint')}>
            <Icon name="info" size={14} />
            {t('status.demo')}
          </span>
        </>
      ) : null}
      <span class="statusbar-gap" />
      {running ? (
        <button type="button" class="status-item" onClick={() => (page.value = 'copy')}>
          <Icon name={l.about.direction === 'toPc' ? 'toPc' : 'toPhone'} size={14} />
          {t('status.copying', { done: formatBytes(l.done), total: formatBytes(l.bytes) })}
        </button>
      ) : null}
      <span class="sep" />
      <span class="status-item mono">{t('status.version', { version: __APP_VERSION__ })}</span>
      <button type="button" class="status-item" onClick={() => void api.openUrl(REPO_URL)} aria-label={t('status.github')} title={t('status.github')}>
        <Icon name="github" size={14} />
      </button>
    </footer>
  );
}

export function App() {
  useEffect(() => {
    void loadSettings();
    void loadHistory();
    void resume();
    startPolling();
  }, []);

  const currentPage = page.value;
  const l = live.value;
  return (
    <div class="app">
      <a class="skip-link" href="#main">
        {t('nav.label')}
      </a>
      <nav class="sidebar" aria-label={t('nav.label')}>
        <div class="wordmark">
          <Mark />
          <span class="wordmark-text">adbData</span>
        </div>
        <div class="nav">
          {NAV.map((item) => {
            const count = item.count?.();
            const running = item.page === 'copy' && l && !l.result;
            return (
              <button
                key={item.page}
                type="button"
                class="nav-item"
                aria-current={currentPage === item.page ? 'page' : undefined}
                onClick={() => (page.value = item.page)}
              >
                <Icon name={item.icon} size={19} />
                <span>{t(`nav.${item.page}`)}</span>
                {running ? (
                  <span class="nav-count num">{formatNumber(l.bytes ? Math.floor((l.done / l.bytes) * 100) : 0)}%</span>
                ) : count ? (
                  <span class="nav-count">{formatNumber(count)}</span>
                ) : null}
              </button>
            );
          })}
        </div>
        <SidebarPhone />
      </nav>
      <main id="main" class="main" tabIndex={-1}>
        {currentPage === 'phone' ? <Phone /> : null}
        {currentPage === 'copy' ? <Copy /> : null}
        {currentPage === 'history' ? <History /> : null}
        {currentPage === 'settings' ? <Settings /> : null}
      </main>
      <StatusBar />
      <Snackbars />
      <ReviewDialog />
      <ConfirmHost />
    </div>
  );
}
