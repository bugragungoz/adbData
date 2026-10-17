/** Where copies go and how, adb, appearance and what adbData is. */
import { useEffect, useState } from 'preact/hooks';
import { api } from '../api';
import type { Existing, Layout, Settings as SettingsType } from '../api/types';
import { LANGUAGES, t } from '../i18n';
import { errorMessage } from '../lib/errors';
import { refreshStatus, status } from '../state/device';
import { saveSettings, settings } from '../state/settings';
import { toast } from '../state/toasts';
import { Button } from '../components/Button';
import { PageHeader, Segmented, TextField } from '../components/Misc';
import { Switch } from '../components/Switch';

export const REPO_URL = 'https://github.com/bugragungoz/adbData';

function Group({ title, children }: { title: string; children: preact.ComponentChildren }) {
  return (
    <section class="settings-group">
      <h2 class="settings-title">{title}</h2>
      <div class="settings-body">{children}</div>
    </section>
  );
}

export function Settings() {
  const s = settings.value;
  const st = status.value;
  const [adbPath, setAdbPath] = useState(s?.adbPath ?? '');
  useEffect(() => setAdbPath(s?.adbPath ?? ''), [s?.adbPath]);
  if (!s) return null;

  const save = async (patch: Partial<SettingsType>) => {
    try {
      await saveSettings(patch);
    } catch (e) {
      toast(errorMessage(e), { tone: 'warn' });
    }
  };

  const pickDestination = async () => {
    const picked = await api.pickFolder(t('settings.pickDestination'), s.destination || s.defaultDestination);
    if (picked) await save({ destination: picked });
  };

  const saveAdbPath = async () => {
    await save({ adbPath });
    await refreshStatus();
  };

  const adb = st?.adb;
  return (
    <div class="view-body">
      <PageHeader title={t('settings.title')} />

      <Group title={t('settings.copies')}>
        <div class="setting-row">
          <span class="setting-label">{t('settings.destination')}</span>
          <p class="path mono">{s.destination || s.defaultDestination}</p>
          <div class="actions">
            <Button icon="folder" onClick={() => void pickDestination()}>
              {t('settings.change')}
            </Button>
            {s.destination ? (
              <Button variant="quiet" onClick={() => void save({ destination: '' })}>
                {t('settings.useDefault')}
              </Button>
            ) : null}
          </div>
          <span class="setting-meta">{t('settings.destinationHint')}</span>
        </div>
        <div class="setting-row">
          <span class="setting-label">{t('review.existing')}</span>
          <Segmented<Existing>
            label={t('review.existing')}
            value={s.existing}
            onChange={(v) => void save({ existing: v })}
            options={[
              { value: 'skip', label: t('options.skip') },
              { value: 'keepBoth', label: t('options.keepBoth') },
              { value: 'replace', label: t('options.replace') },
            ]}
          />
          <span class="setting-meta">{t(`options.${s.existing}Hint`)}</span>
        </div>
        <div class="setting-row">
          <span class="setting-label">{t('review.layout')}</span>
          <Segmented<Layout>
            label={t('review.layout')}
            value={s.layout}
            onChange={(v) => void save({ layout: v })}
            options={[
              { value: 'keep', label: t('options.keep') },
              { value: 'byMonth', label: t('options.byMonth') },
            ]}
          />
        </div>
        <Switch checked={s.keepDates} onChange={(v) => void save({ keepDates: v })} label={t('options.keepDates')} hint={t('options.keepDatesHint')} />
        <Switch checked={s.check} onChange={(v) => void save({ check: v })} label={t('options.check')} hint={t('options.checkHint')} />
        <Switch checked={s.showHidden} onChange={(v) => void save({ showHidden: v })} label={t('settings.showHidden')} hint={t('settings.showHiddenHint')} />
      </Group>

      <Group title={t('settings.adb')}>
        <p class="setting-meta">
          {adb ? t('settings.adbInUse', { version: adb.version, source: t(`settings.adbSource.${adb.source}`) }) : t('settings.adbNone')}
          {adb ? (
            <>
              <br />
              <span class="mono">{adb.path}</span>
            </>
          ) : null}
        </p>
        <div class="form-row">
          <TextField id="adb-path" label={t('settings.adbPath')} value={adbPath} onInput={setAdbPath} placeholder={t('settings.adbPathPlaceholder')} mono />
          <Button onClick={() => void saveAdbPath()} disabled={adbPath.trim() === s.adbPath}>
            {t('settings.save')}
          </Button>
        </div>
        <p class="setting-meta">{t('settings.adbPathHint')}</p>
      </Group>

      <Group title={t('settings.appearance')}>
        <div class="setting-row">
          <span class="setting-label">{t('settings.theme')}</span>
          <Segmented
            label={t('settings.theme')}
            value={s.theme}
            onChange={(v) => void save({ theme: v })}
            options={[
              { value: 'system', label: t('settings.themeSystem') },
              { value: 'dark', label: t('settings.themeDark') },
              { value: 'light', label: t('settings.themeLight') },
            ]}
          />
        </div>
        <div class="setting-row">
          <span class="setting-label">{t('settings.language')}</span>
          <Segmented
            label={t('settings.language')}
            value={s.language}
            onChange={(v) => void save({ language: v })}
            options={[{ value: 'system', label: t('settings.languageSystem') }, ...LANGUAGES.map((l) => ({ value: l.code, label: l.nativeName }))]}
          />
        </div>
      </Group>

      <Group title={t('settings.about')}>
        <p class="about-text">{t('settings.aboutBody')}</p>
        <p class="setting-meta">{t('settings.version', { version: __APP_VERSION__ })}</p>
        <div class="actions">
          <Button variant="quiet" icon="github" onClick={() => void api.openUrl(REPO_URL)}>
            {t('settings.source')}
          </Button>
        </div>
        <p class="setting-meta">{t('settings.license')}</p>
      </Group>
    </div>
  );
}
