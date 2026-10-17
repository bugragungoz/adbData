import { afterEach, describe, expect, it } from 'vitest';
import { formatNumber, setLanguage, t } from '.';

afterEach(() => setLanguage('en'));

describe('t', () => {
  it('fills placeholders and picks the plural form from count', () => {
    setLanguage('en');
    expect(t('review.total', { count: 1, size: '3 MB' })).toBe('1 file, 3 MB');
    expect(t('review.total', { count: 12, size: '40 MB' })).toBe('12 files, 40 MB');
    expect(t('browse.selected', { count: 3 })).toBe('3 selected');
  });

  it('writes numbers the way the language does', () => {
    setLanguage('tr');
    expect(formatNumber(1234.5)).toBe('1.234,5');
    expect(t('review.total', { count: 1200, size: '2 GB' })).toBe('1.200 dosya, 2 GB');
  });

  it('switches language and falls back to the key for an unknown message', () => {
    setLanguage('tr');
    expect(t('nav.phone')).toBe('Telefon');
    expect(t('no.such.key')).toBe('no.such.key');
    setLanguage('xx');
    expect(t('nav.phone')).toBe('Phone');
  });

  it('leaves a placeholder without a value as it is', () => {
    setLanguage('en');
    expect(t('copy.titleToPc')).toBe('Copying from {phone}');
  });
});
