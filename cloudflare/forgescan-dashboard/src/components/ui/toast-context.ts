import * as React from 'react';
import type { Severity } from './severity-badge';

export type ToastVariant = Severity | 'success' | 'neutral';

export interface Toast {
  id: string;
  title: string;
  description?: string;
  variant?: ToastVariant;
  /** Auto-dismiss after N ms. Pass 0 to require manual dismiss. Default 6000. */
  duration?: number;
  /** Optional action button. */
  action?: { label: string; onClick: () => void };
}

export interface ToastContextValue {
  toasts: Toast[];
  toast: (t: Omit<Toast, 'id'>) => string;
  dismiss: (id: string) => void;
}

export const ToastContext = React.createContext<ToastContextValue | null>(null);

export function useToast(): ToastContextValue {
  const ctx = React.useContext(ToastContext);
  if (!ctx) {
    throw new Error('useToast must be used inside <ToastProvider>.');
  }
  return ctx;
}
