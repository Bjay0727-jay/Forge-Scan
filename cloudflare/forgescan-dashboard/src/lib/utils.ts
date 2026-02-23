import { type ClassValue, clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatDate(date: string | Date): string {
  return new Date(date).toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  });
}

export function formatDateTime(date: string | Date): string {
  return new Date(date).toLocaleString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

export function formatRelativeTime(date: string | Date): string {
  const now = new Date();
  const then = new Date(date);
  const diffMs = now.getTime() - then.getTime();
  const diffSecs = Math.floor(diffMs / 1000);
  const diffMins = Math.floor(diffSecs / 60);
  const diffHours = Math.floor(diffMins / 60);
  const diffDays = Math.floor(diffHours / 24);

  if (diffSecs < 60) return 'just now';
  if (diffMins < 60) return `${diffMins}m ago`;
  if (diffHours < 24) return `${diffHours}h ago`;
  if (diffDays < 7) return `${diffDays}d ago`;
  return formatDate(date);
}

export function getSeverityColor(severity: string): string {
  const colors: Record<string, string> = {
    critical: 'text-red-400 bg-red-500/15 border-red-500/30',
    high: 'text-orange-400 bg-orange-500/15 border-orange-500/30',
    medium: 'text-yellow-400 bg-yellow-500/15 border-yellow-500/30',
    low: 'text-green-400 bg-green-500/15 border-green-500/30',
    info: 'text-blue-400 bg-blue-500/15 border-blue-500/30',
  };
  return colors[severity] || colors.info;
}

export function getSeverityBgColor(severity: string): string {
  const colors: Record<string, string> = {
    critical: '#ef4444',
    high: '#f97316',
    medium: '#eab308',
    low: '#22c55e',
    info: '#3b82f6',
  };
  return colors[severity] || colors.info;
}

export function getStatusColor(status: string): string {
  const colors: Record<string, string> = {
    pending: 'text-gray-400 bg-gray-500/15 border-gray-500/30',
    running: 'text-blue-400 bg-blue-500/15 border-blue-500/30',
    completed: 'text-green-400 bg-green-500/15 border-green-500/30',
    failed: 'text-red-400 bg-red-500/15 border-red-500/30',
    cancelled: 'text-gray-400 bg-gray-500/15 border-gray-500/30',
  };
  return colors[status] || colors.pending;
}

export function getStateColor(state: string): string {
  const colors: Record<string, string> = {
    open: 'text-red-400 bg-red-500/15 border-red-500/30',
    acknowledged: 'text-yellow-400 bg-yellow-500/15 border-yellow-500/30',
    resolved: 'text-green-400 bg-green-500/15 border-green-500/30',
    false_positive: 'text-gray-400 bg-gray-500/15 border-gray-500/30',
  };
  return colors[state] || colors.open;
}

export function truncate(str: string | null | undefined, length: number): string {
  if (!str) return '';
  if (str.length <= length) return str;
  return str.slice(0, length) + '...';
}

export function capitalize(str: string): string {
  return str.charAt(0).toUpperCase() + str.slice(1).replace(/_/g, ' ');
}
