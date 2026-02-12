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
    critical: 'text-red-600 bg-red-100 border-red-200',
    high: 'text-orange-600 bg-orange-100 border-orange-200',
    medium: 'text-yellow-600 bg-yellow-100 border-yellow-200',
    low: 'text-green-600 bg-green-100 border-green-200',
    info: 'text-blue-600 bg-blue-100 border-blue-200',
  };
  return colors[severity] || colors.info;
}

export function getSeverityBgColor(severity: string): string {
  const colors: Record<string, string> = {
    critical: '#dc2626',
    high: '#ea580c',
    medium: '#ca8a04',
    low: '#16a34a',
    info: '#2563eb',
  };
  return colors[severity] || colors.info;
}

export function getStatusColor(status: string): string {
  const colors: Record<string, string> = {
    pending: 'text-gray-600 bg-gray-100 border-gray-200',
    running: 'text-blue-600 bg-blue-100 border-blue-200',
    completed: 'text-green-600 bg-green-100 border-green-200',
    failed: 'text-red-600 bg-red-100 border-red-200',
    cancelled: 'text-gray-600 bg-gray-100 border-gray-200',
  };
  return colors[status] || colors.pending;
}

export function getStateColor(state: string): string {
  const colors: Record<string, string> = {
    open: 'text-red-600 bg-red-100 border-red-200',
    acknowledged: 'text-yellow-600 bg-yellow-100 border-yellow-200',
    resolved: 'text-green-600 bg-green-100 border-green-200',
    false_positive: 'text-gray-600 bg-gray-100 border-gray-200',
  };
  return colors[state] || colors.open;
}

export function truncate(str: string, length: number): string {
  if (str.length <= length) return str;
  return str.slice(0, length) + '...';
}

export function capitalize(str: string): string {
  return str.charAt(0).toUpperCase() + str.slice(1).replace(/_/g, ' ');
}
