/** Every copy, newest first: which way, from where to where, how much, and what did not work. */
import { useState } from 'preact/hooks';
import { api } from '../api';
import type { Session } from '../api/types';
import { t } from '../i18n';
import { errorMessage } from '../lib/errors';
import { formatBytes, formatDateTime, formatDuration } from '../lib/format';
import { confirm } from '../state/dialogs';
import { loadHistory, sessions } from '../state/history';
import { toast } from '../state/toasts';
import { Button } from '../components/Button';
import { Icon } from '../components/Icon';
import { EmptyState, PageHeader } from '../components/Misc';
import { Failures, verdict } from './Copy';

function Row({ s }: { s: Session }) {
  const [open, setOpen] = useState(false);
  const v = verdict(s);
  const toPc = s.direction === 'toPc';
  return (
    <li class="history-row">
      <div class="history-head">
        <Icon name={toPc ? 'toPc' : 'toPhone'} size={18} class="accent-ink" />
        <span class="history-title">{t(toPc ? 'history.toPc' : 'history.toPhone', { phone: s.phone })}</span>
        <span class={`badge ${v.warn ? 'badge-warn' : 'badge-ok'}`}>
          <Icon name={v.icon} size={13} />
          {t(`copy.verdict.${v.key}`)}
        </span>
      </div>
      <p class="history-meta">
        {formatDateTime(s.at)} · {t('copy.copiedValue', { count: s.copied, size: formatBytes(s.bytes) })}
        {s.skipped ? ` · ${t('history.skipped', { count: s.skipped })}` : ''} · {formatDuration(s.seconds)}
      </p>
      <p class="history-route mono">
        <span class="truncate" title={s.from}>
          {s.from}
        </span>
        <Icon name="chevronRight" size={13} class="muted" />
        <span class="truncate" title={s.to}>
          {s.to}
        </span>
      </p>
      {s.failedCount > 0 ? (
        <div>
          <button type="button" class="link-button" aria-expanded={open} onClick={() => setOpen(!open)}>
            {open ? t('history.hideFailed') : t('history.showFailed', { count: s.failedCount })}
          </button>
          {open ? <Failures s={s} /> : null}
        </div>
      ) : null}
      {toPc ? (
        <div class="actions">
          <Button size="sm" variant="quiet" icon="open" onClick={() => void api.reveal(s.to)}>
            {t('copy.showFolder')}
          </Button>
        </div>
      ) : null}
    </li>
  );
}

export function History() {
  const list = sessions.value;
  const clear = async () => {
    const ok = await confirm({
      title: t('history.clearTitle'),
      body: t('history.clearBody'),
      confirmLabel: t('history.clear'),
      cancelLabel: t('common.cancel'),
      danger: true,
    });
    if (!ok) return;
    try {
      await api.clearHistory();
      await loadHistory();
    } catch (e) {
      toast(errorMessage(e), { tone: 'warn' });
    }
  };
  return (
    <div class="view-body">
      <PageHeader title={t('history.title')} subtitle={t('history.subtitle')}>
        {list.length ? (
          <Button variant="quiet" icon="trash" onClick={() => void clear()}>
            {t('history.clear')}
          </Button>
        ) : null}
      </PageHeader>
      {list.length === 0 ? (
        <EmptyState icon="history" title={t('history.empty')} />
      ) : (
        <ul class="history-list">
          {list.map((s) => (
            <Row key={s.id} s={s} />
          ))}
        </ul>
      )}
    </div>
  );
}
