import type { JSX } from 'preact';
import { UI_ICONS } from './icons';

interface Props {
  name: string;
  size?: number;
  class?: string;
  title?: string;
}

/** A UI icon. Decorative unless `title` is given. A path written `fill:...` is drawn filled. */
export function Icon({ name, size = 18, class: cls, title }: Props): JSX.Element {
  const paths = UI_ICONS[name] ?? UI_ICONS.info!;
  return (
    <svg
      class={cls ? `icon ${cls}` : 'icon'}
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      stroke-width="1.6"
      stroke-linecap="round"
      stroke-linejoin="round"
      aria-hidden={title ? undefined : 'true'}
      role={title ? 'img' : undefined}
    >
      {title ? <title>{title}</title> : null}
      {paths.map((d) =>
        d.startsWith('fill:') ? <path d={d.slice(5)} key={d} fill="currentColor" stroke="none" /> : <path d={d} key={d} />,
      )}
    </svg>
  );
}
