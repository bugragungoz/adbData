import { t } from '../i18n';
import { dismissToast, toasts } from '../state/toasts';
import { Icon } from './Icon';
import { IconButton } from './IconButton';

const TONE_ICON = { info: 'info', ok: 'checkCircle', warn: 'alert' } as const;

/** Bugra Snackbar stack (added: the stack). Polite live region; warnings stay until closed. */
export function Snackbars() {
  return (
    <div class="snackbars" role="status" aria-live="polite">
      {toasts.value.map((s) => (
        <div class={`bg-snackbar tone-${s.tone}`} key={s.id}>
          <Icon name={TONE_ICON[s.tone]} size={16} class={`tone-icon tone-${s.tone}`} />
          <p>{s.message}</p>
          {s.actionLabel ? (
            <button
              type="button"
              class="bg-btn bg-btn-sm bg-btn-quiet snackbar-action"
              onClick={async () => {
                dismissToast(s.id);
                await s.onAction?.();
              }}
            >
              {s.actionLabel}
            </button>
          ) : null}
          <IconButton label={t('common.close')} icon="close" size="sm" onClick={() => dismissToast(s.id)} />
        </div>
      ))}
    </div>
  );
}
