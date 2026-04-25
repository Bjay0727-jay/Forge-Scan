import * as React from 'react';
import { createPortal } from 'react-dom';
import { AlertTriangle, AlertCircle, CheckCircle2, Info, X } from 'lucide-react';
import { cn } from '@/lib/utils';
import {
  ToastContext,
  type Toast,
  type ToastContextValue,
  type ToastVariant,
} from './toast-context';

export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [toasts, setToasts] = React.useState<Toast[]>([]);
  const timers = React.useRef(new Map<string, ReturnType<typeof setTimeout>>());

  const dismiss = React.useCallback((id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
    const timer = timers.current.get(id);
    if (timer) {
      clearTimeout(timer);
      timers.current.delete(id);
    }
  }, []);

  const toast = React.useCallback<ToastContextValue['toast']>(
    (input) => {
      const id =
        globalThis.crypto && 'randomUUID' in globalThis.crypto
          ? globalThis.crypto.randomUUID()
          : `toast_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
      const next: Toast = { duration: 6000, variant: 'neutral', ...input, id };
      setToasts((prev) => [...prev, next]);
      if (next.duration && next.duration > 0) {
        const timer = setTimeout(() => dismiss(id), next.duration);
        timers.current.set(id, timer);
      }
      return id;
    },
    [dismiss],
  );

  React.useEffect(() => {
    const ref = timers.current;
    return () => {
      ref.forEach((t) => clearTimeout(t));
      ref.clear();
    };
  }, []);

  const value = React.useMemo(() => ({ toasts, toast, dismiss }), [toasts, toast, dismiss]);

  return (
    <ToastContext.Provider value={value}>
      {children}
      <ToastViewport toasts={toasts} onDismiss={dismiss} />
    </ToastContext.Provider>
  );
}

const VARIANT_ICON: Record<ToastVariant, React.ComponentType<{ className?: string }>> = {
  critical: AlertTriangle,
  high:     AlertTriangle,
  medium:   AlertCircle,
  low:      CheckCircle2,
  info:     Info,
  success:  CheckCircle2,
  neutral:  Info,
};

const VARIANT_CLASS: Record<ToastVariant, string> = {
  critical: 'border-severity-critical/40 bg-severity-critical/10 text-foreground',
  high:     'border-severity-high/40     bg-severity-high/10     text-foreground',
  medium:   'border-severity-medium/40   bg-severity-medium/10   text-foreground',
  low:      'border-severity-low/40      bg-severity-low/10      text-foreground',
  info:     'border-severity-info/40     bg-severity-info/10     text-foreground',
  success:  'border-teal-500/40          bg-teal-500/10          text-foreground',
  neutral:  'border-border                bg-card                 text-foreground',
};

const VARIANT_ICON_TONE: Record<ToastVariant, string> = {
  critical: 'text-severity-critical',
  high:     'text-severity-high',
  medium:   'text-severity-medium',
  low:      'text-severity-low',
  info:     'text-severity-info',
  success:  'text-teal-400',
  neutral:  'text-muted-foreground',
};

function ToastViewport({
  toasts,
  onDismiss,
}: {
  toasts: Toast[];
  onDismiss: (id: string) => void;
}) {
  if (typeof document === 'undefined') return null;
  return createPortal(
    <div
      className="pointer-events-none fixed bottom-4 right-4 z-[100] flex w-full max-w-sm flex-col gap-2"
      role="region"
      aria-label="Notifications"
    >
      {toasts.map((t) => {
        const variant: ToastVariant = t.variant ?? 'neutral';
        const Icon = VARIANT_ICON[variant];
        const isLoud = variant === 'critical' || variant === 'high';
        return (
          <div
            key={t.id}
            role={isLoud ? 'alert' : 'status'}
            aria-live={isLoud ? 'assertive' : 'polite'}
            className={cn(
              'pointer-events-auto rounded-lg border p-3 shadow-forge-pop',
              'animate-forge-toast-in',
              VARIANT_CLASS[variant],
            )}
          >
            <div className="flex items-start gap-3">
              <Icon className={cn('mt-0.5 h-4 w-4 shrink-0', VARIANT_ICON_TONE[variant])} />
              <div className="min-w-0 flex-1">
                <p className="text-sm font-semibold leading-tight">{t.title}</p>
                {t.description && (
                  <p className="mt-1 text-xs text-muted-foreground">{t.description}</p>
                )}
                {t.action && (
                  <button
                    type="button"
                    onClick={() => {
                      t.action!.onClick();
                      onDismiss(t.id);
                    }}
                    className="mt-2 text-xs font-semibold text-teal-400 underline-offset-2 hover:underline"
                  >
                    {t.action.label}
                  </button>
                )}
              </div>
              <button
                type="button"
                aria-label="Dismiss notification"
                onClick={() => onDismiss(t.id)}
                className="rounded p-0.5 text-muted-foreground transition-colors hover:bg-white/5 hover:text-foreground"
              >
                <X className="h-3.5 w-3.5" />
              </button>
            </div>
          </div>
        );
      })}
    </div>,
    document.body,
  );
}
