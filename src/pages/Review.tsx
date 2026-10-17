/**
 * The review before a copy: where from, where to, what to do with files already there, and what
 * the copy will do. Nothing is copied until "Start" is pressed.
 */
import { useState } from 'preact/hooks';
import { api } from '../api';
import type { CopyOptions, Existing, Layout } from '../api/types';
import { t } from '../i18n';
import { errorMessage } from '../lib/errors';
import { formatBytes } from '../lib/format';
import { closeReview, plan, review, start, type Review } from '../state/copy';
import { toast } from '../state/toasts';
import { Button } from '../components/Button';
import { Dialog } from '../components/Dialog';
import { Note, Segmented } from '../components/Misc';
import { Switch } from '../components/Switch';

function replan(r: Review, options: Partial<CopyOptions>, dest?: string) {
  const request = { ...r.request, options: { ...r.request.options, ...options }, ...(dest !== undefined ? { dest } : {}) };
  void plan({ ...r, request } as Review);
}

export function ReviewDialog() {
  const r = review.value;
  const [starting, setStarting] = useState(false);
  if (!r) return null;
  const s = r.summary;
  const o = r.request.options;
  const toPc = r.direction === 'toPc';
  const short = s && s.free != null && s.bytes > s.free;

  const begin = async () => {
    setStarting(true);
    try {
      await start();
    } catch (e) {
      toast(errorMessage(e), { tone: 'warn' });
    } finally {
      setStarting(false);
    }
  };

  const change = async () => {
    if (r.direction !== 'toPc') return;
    const picked = await api.pickFolder(t('review.pickTo'), s?.to ?? null);
    if (picked) replan(r, {}, picked);
  };

  const from = r.direction === 'toPc' ? (r.request.names.length === 1 ? `${r.request.base.replace(/\/$/, '')}/${r.request.names[0]}` : r.request.base) : r.request.paths.length === 1 ? r.request.paths[0]! : t('review.pcItems', { count: r.request.paths.length });

  return (
    <Dialog
      title={t(toPc ? 'review.titleToPc' : 'review.titleToPhone')}
      onClose={closeReview}
      size="wide"
      busy={starting}
      actions={
        <>
          <Button variant="quiet" onClick={closeReview} disabled={starting}>
            {t('common.cancel')}
          </Button>
          <Button variant="primary" icon={toPc ? 'toPc' : 'toPhone'} onClick={() => void begin()} disabled={!s || r.planning || starting || s.files === 0 || !!short} data-autofocus>
            {s && s.files > 0 ? t('review.start', { count: s.files }) : t('review.startNone')}
          </Button>
        </>
      }
    >
      <div class="review-where">
        <dl class="facts review-facts">
          <div>
            <dt>{t('review.from')}</dt>
            <dd class="mono">{from}</dd>
          </div>
          <div>
            <dt>{t('review.to')}</dt>
            <dd class="mono">{s?.to ?? (r.direction === 'toPhone' ? r.request.dest : '')}</dd>
          </div>
        </dl>
        {toPc ? (
          <div class="actions">
            <Button size="sm" icon="folder" onClick={() => void change()}>
              {t('review.change')}
            </Button>
          </div>
        ) : null}
      </div>

      <div class="review-options">
        <div class="setting-row">
          <span class="setting-label">{t('review.existing')}</span>
          <Segmented<Existing>
            label={t('review.existing')}
            value={o.existing}
            onChange={(v) => replan(r, { existing: v })}
            options={[
              { value: 'skip', label: t('options.skip') },
              { value: 'keepBoth', label: t('options.keepBoth') },
              { value: 'replace', label: t('options.replace') },
            ]}
          />
          <span class="setting-meta">{t(`options.${o.existing}Hint`)}</span>
        </div>

        {toPc ? (
          <div class="setting-row">
            <span class="setting-label">{t('review.layout')}</span>
            <Segmented<Layout>
              label={t('review.layout')}
              value={o.layout}
              onChange={(v) => replan(r, { layout: v })}
              options={[
                { value: 'keep', label: t('options.keep') },
                { value: 'byMonth', label: t('options.byMonth') },
              ]}
            />
          </div>
        ) : null}

        <div class="review-switches">
          {toPc ? <Switch checked={o.keepDates} onChange={(v) => replan(r, { keepDates: v })} label={t('options.keepDates')} hint={t('options.keepDatesHint')} /> : null}
          <Switch checked={o.check} onChange={(v) => replan(r, { check: v })} label={t('options.check')} hint={t('options.checkHint')} />
        </div>
      </div>

      <section class="review-summary" aria-live="polite" aria-busy={r.planning}>
        {r.error ? (
          <Note icon="alert" tone="warn" title={t('review.planFailed')}>
            {r.error}
          </Note>
        ) : !s || r.planning ? (
          <p class="muted">{t('review.planning')}</p>
        ) : (
          <>
            <p class="review-total">
              {s.files > 0 ? t('review.total', { count: s.files, size: formatBytes(s.bytes) }) : t('review.nothing')}
            </p>
            <ul class="review-lines">
              {s.skipped > 0 ? <li>{t('review.skipped', { count: s.skipped, size: formatBytes(s.skippedBytes) })}</li> : null}
              {s.filtered > 0 ? <li>{t('review.filtered', { count: s.filtered })}</li> : null}
              {s.renamed > 0 ? <li>{t('review.renamed', { count: s.renamed })}</li> : null}
              {s.numbered > 0 ? <li>{t('review.numbered', { count: s.numbered })}</li> : null}
              {s.replaced > 0 ? <li>{t('review.replaced', { count: s.replaced })}</li> : null}
              {s.unreadable > 0 ? <li>{t('review.unreadable', { count: s.unreadable })}</li> : null}
              {s.free != null ? <li>{t(toPc ? 'review.freePc' : 'review.freePhone', { size: formatBytes(s.free) })}</li> : null}
            </ul>
            {short ? (
              <Note icon="alert" tone="warn" title={t('review.noRoomTitle')}>
                {t('review.noRoomBody', { need: formatBytes(s.bytes), free: formatBytes(s.free ?? 0) })}
              </Note>
            ) : null}
          </>
        )}
      </section>
    </Dialog>
  );
}
