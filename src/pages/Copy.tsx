/** The copy running now (or the last one): how far it is, how fast, and how it ended. */
import { api } from '../api';
import type { Live, Session } from '../api/types';
import { formatNumber, t } from '../i18n';
import { formatBytes, formatDuration, formatSpeed } from '../lib/format';
import { live, stop } from '../state/copy';
import { page } from '../state/ui';
import { Button } from '../components/Button';
import { Icon } from '../components/Icon';
import { EmptyState, Meter, Note, PageHeader } from '../components/Misc';

function Running({ l }: { l: Live }) {
  const elapsed = Math.max(0.5, (Date.now() - l.started) / 1000);
  const speed = l.done / elapsed;
  const left = speed > 0 ? (l.bytes - l.done) / speed : 0;
  const share = l.bytes > 0 ? l.done / l.bytes : 0;
  return (
    <section class="card copy-card" aria-live="polite">
      <div class="copy-figures">
        <strong class="copy-percent num">{formatNumber(Math.floor(share * 100))}%</strong>
        <span class="muted num">{t('copy.of', { done: formatBytes(l.done), total: formatBytes(l.bytes) })}</span>
      </div>
      <Meter value={share} label={t('copy.progress')} />
      <dl class="facts">
        <div>
          <dt>{t('copy.files')}</dt>
          <dd class="num">{t('copy.fileOf', { n: Math.min(l.index + 1, l.files), total: l.files })}</dd>
        </div>
        <div>
          <dt>{t('copy.speed')}</dt>
          <dd class="num">{formatSpeed(speed)}</dd>
        </div>
        <div>
          <dt>{t('copy.left')}</dt>
          <dd class="num">{l.checking ? t('copy.checking', { done: l.checking[0], total: l.checking[1] }) : formatDuration(left)}</dd>
        </div>
      </dl>
      <p class="copy-current truncate mono" title={l.current}>
        {l.current}
      </p>
      <div class="actions">
        <Button variant="danger" icon="stop" onClick={() => void stop()} disabled={l.stopping}>
          {l.stopping ? t('copy.stopping') : t('copy.stop')}
        </Button>
      </div>
    </section>
  );
}

/** The headline of a finished copy and its tone. */
export function verdict(s: Session): { key: string; icon: string; warn: boolean } {
  if (s.diskFull) return { key: 'diskFull', icon: 'alert', warn: true };
  if (s.disconnected) return { key: 'disconnected', icon: 'unlink', warn: true };
  if (s.stopped) return { key: 'stopped', icon: 'stop', warn: false };
  if (s.failedCount > 0) return { key: 'someFailed', icon: 'alert', warn: true };
  return { key: 'done', icon: 'checkCircle', warn: false };
}

export function Failures({ s }: { s: Session }) {
  if (s.failed.length === 0) return null;
  return (
    <ul class="history-items" aria-label={t('copy.failedList')}>
      {s.failed.map((f) => (
        <li key={f.path}>
          <Icon name="alert" size={14} class="tone-warn" />
          <span class="truncate mono" title={f.path}>
            {f.path}
          </span>
          <span class="muted">{t(`failure.${f.code}`, { detail: f.detail })}</span>
        </li>
      ))}
      {s.failedCount > s.failed.length ? <li class="muted">{t('copy.moreFailed', { count: s.failedCount - s.failed.length })}</li> : null}
    </ul>
  );
}

function Finished({ s }: { s: Session }) {
  const v = verdict(s);
  return (
    <section class="card copy-card">
      <h2 class={`card-title copy-verdict ${v.warn ? 'tone-warn' : 'tone-ok'}`}>
        <Icon name={v.icon} size={20} />
        {t(`copy.verdict.${v.key}`)}
      </h2>
      <dl class="facts">
        <div>
          <dt>{t('copy.copied')}</dt>
          <dd class="num">{t('copy.copiedValue', { count: s.copied, size: formatBytes(s.bytes) })}</dd>
        </div>
        <div>
          <dt>{t('copy.skipped')}</dt>
          <dd class="num">{formatNumber(s.skipped)}</dd>
        </div>
        <div>
          <dt>{t('copy.took')}</dt>
          <dd class="num">{formatDuration(s.seconds)}</dd>
        </div>
        <div>
          <dt>{t('copy.average')}</dt>
          <dd class="num">{s.seconds > 0 ? formatSpeed(s.bytes / s.seconds) : '-'}</dd>
        </div>
      </dl>
      {s.checked > 0 ? <p class="setting-meta">{t('copy.checked', { count: s.checked })}</p> : null}
      {s.checkUnavailable ? (
        <Note icon="info" title={t('copy.checkUnavailableTitle')}>
          {t('copy.checkUnavailableBody')}
        </Note>
      ) : null}
      {s.disconnected ? (
        <Note icon="unlink" tone="warn" title={t('copy.disconnectedTitle')}>
          {t('copy.disconnectedBody')}
        </Note>
      ) : null}
      <Failures s={s} />
      <div class="actions">
        {s.direction === 'toPc' ? (
          <Button variant="primary" icon="open" onClick={() => void api.reveal(s.to)}>
            {t('copy.showFolder')}
          </Button>
        ) : null}
        <Button variant="quiet" icon="phone" onClick={() => (page.value = 'phone')}>
          {t('copy.backToPhone')}
        </Button>
      </div>
    </section>
  );
}

export function Copy() {
  const l = live.value;
  if (!l) {
    return (
      <div class="view-body">
        <PageHeader title={t('copy.title')} />
        <EmptyState icon="toPc" title={t('copy.none')} body={t('copy.noneBody')} />
      </div>
    );
  }
  const toPc = l.about.direction === 'toPc';
  return (
    <div class="view-body">
      <PageHeader
        title={l.result ? t(toPc ? 'copy.titleDoneToPc' : 'copy.titleDoneToPhone') : t(toPc ? 'copy.titleToPc' : 'copy.titleToPhone', { phone: l.about.phone })}
      />
      <dl class="facts copy-route">
        <div>
          <dt>{t('review.from')}</dt>
          <dd class="mono">{l.about.from}</dd>
        </div>
        <div>
          <dt>{t('review.to')}</dt>
          <dd class="mono">{l.about.to}</dd>
        </div>
      </dl>
      {l.result ? <Finished s={l.result} /> : <Running l={l} />}
    </div>
  );
}
