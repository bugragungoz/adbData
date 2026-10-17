import type { JSX } from 'preact';
import { Icon } from './Icon';

export interface IconButtonProps extends Omit<JSX.ButtonHTMLAttributes<HTMLButtonElement>, 'icon' | 'size' | 'label' | 'type'> {
  type?: 'button' | 'submit';
  label: string;
  icon: string;
  size?: 'md' | 'sm';
  pressed?: boolean;
  disabled?: boolean;
}

/** Bugra IconButton: always labelled; the label is also the tooltip. */
export function IconButton({ label, icon, size = 'md', pressed, type = 'button', class: cls, ...rest }: IconButtonProps) {
  return (
    <button
      type={type}
      class={['bg-iconbtn', size === 'sm' && 'bg-iconbtn-sm', pressed && 'is-pressed', cls].filter(Boolean).join(' ')}
      aria-label={label}
      title={label}
      aria-pressed={pressed === undefined ? undefined : pressed}
      {...rest}
    >
      <Icon name={icon} size={size === 'sm' ? 16 : 19} />
    </button>
  );
}
