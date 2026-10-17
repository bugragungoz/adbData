import type { ComponentChildren, JSX } from 'preact';
import { Icon } from './Icon';

type Variant = 'outline' | 'primary' | 'quiet' | 'danger';

export interface ButtonProps extends Omit<JSX.ButtonHTMLAttributes<HTMLButtonElement>, 'icon' | 'size' | 'type'> {
  variant?: Variant;
  size?: 'md' | 'sm';
  icon?: string;
  type?: 'button' | 'submit' | 'reset';
  disabled?: boolean;
  children?: ComponentChildren;
}

/** Bugra Button: a pill. `quiet` (no outline) and `danger` (warn outline) are additions (added). */
export function Button({ variant = 'outline', size = 'md', icon, type = 'button', class: cls, children, ...rest }: ButtonProps) {
  const classes = ['bg-btn', variant !== 'outline' && `bg-btn-${variant}`, size === 'sm' && 'bg-btn-sm', cls].filter(Boolean).join(' ');
  return (
    <button type={type} class={classes} {...rest}>
      {icon ? <Icon name={icon} size={16} /> : null}
      {children}
    </button>
  );
}
