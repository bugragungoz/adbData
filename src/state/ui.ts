/** Which page is open. */
import { signal } from '@preact/signals';

export type Page = 'phone' | 'copy' | 'history' | 'settings';

export const page = signal<Page>('phone');
