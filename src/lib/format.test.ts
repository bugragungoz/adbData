import { afterEach, describe, expect, it } from 'vitest';
import { setLanguage } from '../i18n';
import { formatAgo, formatBytes, formatDateTime } from './format';

afterEach(() => setLanguage('en'));

describe('format', () => {
  it('scales bytes with one decimal below ten', () => {
    setLanguage('en');
    expect(formatBytes(0)).toBe('0 B');
    expect(formatBytes(999)).toBe('999 B');
    expect(formatBytes(7_340_032)).toBe('7.3 MB');
    expect(formatBytes(12_345_678)).toBe('12 MB');
    setLanguage('tr');
    expect(formatBytes(7_340_032)).toBe('7,3 MB');
  });

  it('says how long ago in whole units', () => {
    setLanguage('en');
    const now = 10_000_000_000;
    expect(formatAgo(null, now)).toBe('never');
    expect(formatAgo(now - 20_000, now)).toBe('just now');
    expect(formatAgo(now - 4 * 60_000, now)).toBe('4 min ago');
    expect(formatAgo(now - 2 * 3_600_000, now)).toBe('2 h ago');
    expect(formatAgo(now - 3 * 86_400_000, now)).toBe('3 days ago');
    expect(formatAgo(now - 86_400_000, now)).toBe('1 day ago');
  });

  it('writes dates in the language chosen', () => {
    const at = Date.UTC(2026, 9, 16, 12, 0);
    setLanguage('en');
    expect(formatDateTime(at)).toMatch(/Oct 16, 2026/);
    setLanguage('tr');
    expect(formatDateTime(at)).toMatch(/16 Eki 2026/);
  });
});
