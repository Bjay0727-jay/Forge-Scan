import { describe, it, expect } from 'vitest';
import {
  cn,
  formatDate,
  formatDateTime,
  formatRelativeTime,
  getSeverityColor,
  getSeverityBgColor,
  getStatusColor,
  getStateColor,
  truncate,
  capitalize,
} from './utils';

// --- cn ---

describe('cn', () => {
  it('merges class names', () => {
    expect(cn('foo', 'bar')).toBe('foo bar');
  });

  it('handles Tailwind conflicts — later wins', () => {
    const result = cn('p-4', 'p-2');
    expect(result).toBe('p-2');
  });

  it('handles conditional classes', () => {
    expect(cn('base', false && 'hidden')).toBe('base');
    expect(cn('base', true && 'visible')).toBe('base visible');
  });

  it('handles undefined and null inputs', () => {
    expect(cn('base', undefined, null)).toBe('base');
  });

  it('handles empty call', () => {
    expect(cn()).toBe('');
  });
});

// --- formatDate ---

describe('formatDate', () => {
  it('formats ISO string to readable date', () => {
    const result = formatDate('2025-01-15T12:00:00Z');
    // Locale-dependent, but should contain "Jan", "15", "2025"
    expect(result).toContain('Jan');
    expect(result).toContain('15');
    expect(result).toContain('2025');
  });

  it('handles Date object input', () => {
    const result = formatDate(new Date('2024-06-01T00:00:00Z'));
    expect(result).toContain('2024');
  });
});

// --- formatDateTime ---

describe('formatDateTime', () => {
  it('includes date and time components', () => {
    const result = formatDateTime('2025-03-20T14:30:00Z');
    // Should contain date parts
    expect(result).toContain('Mar');
    expect(result).toContain('20');
    expect(result).toContain('2025');
  });

  it('handles Date object input', () => {
    const result = formatDateTime(new Date('2024-12-25T08:00:00Z'));
    expect(result).toContain('Dec');
    expect(result).toContain('25');
  });
});

// --- formatRelativeTime ---

describe('formatRelativeTime', () => {
  it('returns "just now" for < 60 seconds ago', () => {
    const recent = new Date(Date.now() - 30 * 1000).toISOString();
    expect(formatRelativeTime(recent)).toBe('just now');
  });

  it('returns "Xm ago" for < 60 minutes ago', () => {
    const fiveMinAgo = new Date(Date.now() - 5 * 60 * 1000).toISOString();
    expect(formatRelativeTime(fiveMinAgo)).toBe('5m ago');
  });

  it('returns "Xh ago" for < 24 hours ago', () => {
    const threeHoursAgo = new Date(Date.now() - 3 * 60 * 60 * 1000).toISOString();
    expect(formatRelativeTime(threeHoursAgo)).toBe('3h ago');
  });

  it('returns "Xd ago" for < 7 days ago', () => {
    const twoDaysAgo = new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString();
    expect(formatRelativeTime(twoDaysAgo)).toBe('2d ago');
  });

  it('falls back to formatted date for >= 7 days ago', () => {
    const tenDaysAgo = new Date(Date.now() - 10 * 24 * 60 * 60 * 1000).toISOString();
    const result = formatRelativeTime(tenDaysAgo);
    // Should be a formatted date, not relative
    expect(result).not.toContain('ago');
    expect(result).not.toBe('just now');
  });
});

// --- getSeverityColor ---

describe('getSeverityColor', () => {
  it('returns red classes for critical', () => {
    expect(getSeverityColor('critical')).toContain('text-red');
  });

  it('returns orange classes for high', () => {
    expect(getSeverityColor('high')).toContain('text-orange');
  });

  it('returns yellow classes for medium', () => {
    expect(getSeverityColor('medium')).toContain('text-yellow');
  });

  it('returns green classes for low', () => {
    expect(getSeverityColor('low')).toContain('text-green');
  });

  it('returns blue classes for info', () => {
    expect(getSeverityColor('info')).toContain('text-blue');
  });

  it('returns default (blue) for unknown severity', () => {
    expect(getSeverityColor('unknown')).toContain('text-blue');
  });
});

// --- getSeverityBgColor ---

describe('getSeverityBgColor', () => {
  it('returns correct hex for critical', () => {
    expect(getSeverityBgColor('critical')).toBe('#ef4444');
  });

  it('returns correct hex for high', () => {
    expect(getSeverityBgColor('high')).toBe('#f97316');
  });

  it('returns correct hex for medium', () => {
    expect(getSeverityBgColor('medium')).toBe('#eab308');
  });

  it('returns correct hex for low', () => {
    expect(getSeverityBgColor('low')).toBe('#22c55e');
  });

  it('returns correct hex for info', () => {
    expect(getSeverityBgColor('info')).toBe('#3b82f6');
  });

  it('returns blue default for unknown', () => {
    expect(getSeverityBgColor('unknown')).toBe('#3b82f6');
  });
});

// --- getStatusColor ---

describe('getStatusColor', () => {
  it('returns gray for pending', () => {
    expect(getStatusColor('pending')).toContain('text-gray');
  });

  it('returns blue for running', () => {
    expect(getStatusColor('running')).toContain('text-blue');
  });

  it('returns green for completed', () => {
    expect(getStatusColor('completed')).toContain('text-green');
  });

  it('returns red for failed', () => {
    expect(getStatusColor('failed')).toContain('text-red');
  });

  it('returns gray for cancelled', () => {
    expect(getStatusColor('cancelled')).toContain('text-gray');
  });

  it('defaults to pending for unknown status', () => {
    expect(getStatusColor('unknown')).toContain('text-gray');
  });
});

// --- getStateColor ---

describe('getStateColor', () => {
  it('returns red for open', () => {
    expect(getStateColor('open')).toContain('text-red');
  });

  it('returns yellow for acknowledged', () => {
    expect(getStateColor('acknowledged')).toContain('text-yellow');
  });

  it('returns green for resolved', () => {
    expect(getStateColor('resolved')).toContain('text-green');
  });

  it('returns gray for false_positive', () => {
    expect(getStateColor('false_positive')).toContain('text-gray');
  });

  it('defaults to open for unknown state', () => {
    expect(getStateColor('unknown')).toContain('text-red');
  });
});

// --- truncate ---

describe('truncate', () => {
  it('returns string unchanged when <= length', () => {
    expect(truncate('hello', 10)).toBe('hello');
    expect(truncate('hello', 5)).toBe('hello');
  });

  it('truncates and adds "..." when > length', () => {
    expect(truncate('hello world', 5)).toBe('hello...');
  });

  it('handles empty string', () => {
    expect(truncate('', 10)).toBe('');
  });

  it('handles length of 0', () => {
    expect(truncate('hello', 0)).toBe('...');
  });
});

// --- capitalize ---

describe('capitalize', () => {
  it('capitalizes first letter', () => {
    expect(capitalize('hello')).toBe('Hello');
  });

  it('replaces underscores with spaces', () => {
    expect(capitalize('false_positive')).toBe('False positive');
  });

  it('handles already capitalized string', () => {
    expect(capitalize('Hello')).toBe('Hello');
  });

  it('handles empty string', () => {
    expect(capitalize('')).toBe('');
  });

  it('handles single character', () => {
    expect(capitalize('a')).toBe('A');
  });

  it('handles multi-word with underscores', () => {
    expect(capitalize('scan_admin')).toBe('Scan admin');
  });
});
