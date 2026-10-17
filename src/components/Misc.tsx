import type { ComponentChildren } from 'preact';
import { t } from '../i18n';
import { Icon } from './Icon';
import { IconButton } from './IconButton';

export function EmptyState({ icon, title, body, children }: { icon: string; title: string; body?: string; children?: ComponentChildren }) {
  return (
    <div class="empty-state">
      <div class="empty-icon">
        <Icon name={icon} size={24} />
      </div>
      <h2>{title}</h2>
      {body ? <p>{body}</p> : null}
      {children ? <div class="empty-actions">{children}</div> : null}
    </div>
  );
}

export function Note({ icon = 'info', tone, title, children }: { icon?: string; tone?: 'warn' | 'info'; title: string; children?: ComponentChildren }) {
  return (
    <div class={`bg-note ${tone ? `note-${tone}` : ''}`}>
      <Icon name={icon} size={18} class={tone ? `tone-${tone}` : 'muted'} />
      <p>
        <strong>{title}</strong>
        {children}
      </p>
    </div>
  );
}

export function SearchBox({ value, onInput, placeholder }: { value: string; onInput: (v: string) => void; placeholder: string }) {
  return (
    <label class="search-box">
      <Icon name="search" size={16} />
      <input type="search" value={value} placeholder={placeholder} aria-label={placeholder} onInput={(e) => onInput((e.currentTarget as HTMLInputElement).value)} />
      {value ? <IconButton label={t('common.clearSearch')} icon="close" size="sm" onClick={() => onInput('')} /> : null}
    </label>
  );
}

export function PageHeader({ title, subtitle, children }: { title: string; subtitle?: string; children?: ComponentChildren }) {
  return (
    <header class="page-header">
      <div class="page-heading">
        <h1 class="view-title">{title}</h1>
        {subtitle ? <p class="muted page-subtitle">{subtitle}</p> : null}
      </div>
      {children ? <div class="page-actions">{children}</div> : null}
    </header>
  );
}

export function TextField({
  label,
  value,
  onInput,
  placeholder,
  hint,
  mono,
  inputMode,
  id,
}: {
  label: string;
  value: string;
  onInput: (v: string) => void;
  placeholder?: string;
  hint?: string;
  mono?: boolean;
  inputMode?: 'numeric' | 'text' | 'decimal';
  id: string;
}) {
  return (
    <div class="bg-field">
      <label class="bg-field-label" for={id}>
        {label}
      </label>
      <input
        id={id}
        class={`bg-input ${mono ? 'mono' : ''}`}
        value={value}
        placeholder={placeholder}
        inputMode={inputMode}
        spellcheck={false}
        autocomplete="off"
        onInput={(e) => onInput((e.currentTarget as HTMLInputElement).value)}
        aria-describedby={hint ? `${id}-hint` : undefined}
      />
      {hint ? (
        <p class="bg-field-msg" id={`${id}-hint`}>
          {hint}
        </p>
      ) : null}
    </div>
  );
}

/** A thin bar for how far something has come; the text beside it carries the value. */
export function Meter({ value, label }: { value: number; label: string }) {
  const pct = Math.round(Math.max(0, Math.min(1, value)) * 100);
  return (
    <div class="meter" role="progressbar" aria-label={label} aria-valuemin={0} aria-valuemax={100} aria-valuenow={pct}>
      <div class="meter-fill" style={{ width: `${pct}%` }} />
    </div>
  );
}

/** A pill group where one option is chosen (role radiogroup). */
export function Segmented<T extends string>({ label, value, options, onChange }: { label: string; value: T; options: { value: T; label: string }[]; onChange: (v: T) => void }) {
  return (
    <div class="tabs" role="radiogroup" aria-label={label}>
      {options.map((o) => (
        <button key={o.value} type="button" role="radio" class="tab" aria-selected={o.value === value} aria-checked={o.value === value} onClick={() => onChange(o.value)}>
          {o.label}
        </button>
      ))}
    </div>
  );
}
