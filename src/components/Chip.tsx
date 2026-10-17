import type { ComponentChildren, JSX } from 'preact';

export interface ChipProps extends Omit<JSX.ButtonHTMLAttributes<HTMLButtonElement>, 'selected' | 'type'> {
  selected?: boolean;
  children?: ComponentChildren;
}

/** Bugra Chip (added in Bugra): a filter toggle; selected chips show a check, never color alone. */
export function Chip({ selected = false, class: cls, children, ...rest }: ChipProps) {
  return (
    <button type="button" class={['bg-chip', cls].filter(Boolean).join(' ')} aria-pressed={selected} {...rest}>
      {children}
    </button>
  );
}
