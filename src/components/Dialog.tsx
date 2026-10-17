import type { ComponentChildren } from 'preact';
import { useId, useLayoutEffect, useRef } from 'preact/hooks';
import { t } from '../i18n';
import { IconButton } from './IconButton';

export interface DialogProps {
  title: string;
  onClose: () => void;
  children?: ComponentChildren;
  actions?: ComponentChildren;
  size?: 'question' | 'form' | 'wide' | 'list';
  /** Escape and the scrim close the dialog unless busy. */
  busy?: boolean;
  describedBy?: string;
  initialFocus?: string;
}

const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

/**
 * Bugra Dialog (added in Bugra): modal on a scrim, focus moves in and is trapped, Escape closes,
 * focus returns to what opened it. Only floating layers carry a shadow.
 */
export function Dialog({ title, onClose, children, actions, size = 'form', busy = false, describedBy, initialFocus }: DialogProps) {
  const ref = useRef<HTMLDivElement>(null);
  const titleId = useId();
  const closeRef = useRef(onClose);
  closeRef.current = onClose;
  const busyRef = useRef(busy);
  busyRef.current = busy;

  // Layout effect: focus moves in before the first paint, so a key pressed right away reaches the dialog.
  useLayoutEffect(() => {
    const opener = document.activeElement as HTMLElement | null;
    const box = ref.current!;
    const first = (initialFocus && box.querySelector<HTMLElement>(initialFocus)) || box.querySelector<HTMLElement>('[data-autofocus]') ||
      box.querySelector<HTMLElement>('.bg-dialog-body ' + FOCUSABLE) || box.querySelector<HTMLElement>(FOCUSABLE);
    first?.focus();
    const topmost = () => {
      const scrims = document.querySelectorAll('.bg-scrim');
      return scrims[scrims.length - 1] === box.parentElement;
    };
    // Escape is heard on the document (wherever focus is) but only by the topmost dialog.
    const onDocKey = (e: KeyboardEvent) => {
      if (e.key !== 'Escape' || !topmost()) return;
      e.stopPropagation();
      e.preventDefault();
      if (!busyRef.current) closeRef.current();
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== 'Tab') return;
      const items = [...box.querySelectorAll<HTMLElement>(FOCUSABLE)].filter((el) => el.offsetParent !== null || el === document.activeElement);
      if (!items.length) return;
      const firstEl = items[0]!;
      const lastEl = items[items.length - 1]!;
      if (e.shiftKey && document.activeElement === firstEl) {
        e.preventDefault();
        lastEl.focus();
      } else if (!e.shiftKey && document.activeElement === lastEl) {
        e.preventDefault();
        firstEl.focus();
      }
    };
    document.addEventListener('keydown', onDocKey, true);
    box.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('keydown', onDocKey, true);
      box.removeEventListener('keydown', onKey);
      opener?.focus?.();
    };
  }, []);

  return (
    <div class="bg-scrim" onMouseDown={(e) => { if (e.target === e.currentTarget && !busy) onClose(); }}>
      <div ref={ref} class={`bg-dialog bg-dialog-${size}`} role="dialog" aria-modal="true" aria-labelledby={titleId} aria-describedby={describedBy}>
        <header class="bg-dialog-head">
          <h2 class="bg-dialog-title" id={titleId}>
            {title}
          </h2>
          <IconButton label={t('common.close')} icon="close" size="sm" onClick={onClose} disabled={busy} />
        </header>
        <div class="bg-dialog-body">{children}</div>
        {actions ? <footer class="bg-dialog-actions">{actions}</footer> : null}
      </div>
    </div>
  );
}
