import * as React from 'react';
import { cn } from '@/lib/utils';

export interface LivePulseProps extends React.HTMLAttributes<HTMLSpanElement> {
  /** Color token for the dot. Defaults to teal-400. */
  tone?: 'teal' | 'critical' | 'high' | 'medium' | 'low' | 'info';
  /** Diameter in px. Default 8. */
  size?: number;
  /** Optional accessible label for the pulse. */
  label?: string;
}

const TONE_VAR: Record<NonNullable<LivePulseProps['tone']>, string> = {
  teal:     'var(--forge-teal-400)',
  critical: 'var(--forge-sev-critical)',
  high:     'var(--forge-sev-high)',
  medium:   'var(--forge-sev-medium)',
  low:      'var(--forge-sev-low)',
  info:     'var(--forge-sev-info)',
};

/**
 * Live-stream heartbeat. Use to mark "is this data alive?"
 * (live alert queue, active scan, war-room timeline, etc.).
 * Animates only when prefers-reduced-motion is not set.
 */
export const LivePulse = React.forwardRef<HTMLSpanElement, LivePulseProps>(
  ({ tone = 'teal', size = 8, label = 'Live', className, ...props }, ref) => (
    <span
      ref={ref}
      role="img"
      aria-label={label}
      title={label}
      className={cn('inline-flex items-center justify-center', className)}
      style={{ width: size, height: size }}
      {...props}
    >
      <span
        aria-hidden
        className="absolute h-full w-full rounded-full forge-pulse-dot"
        style={{ background: TONE_VAR[tone], opacity: 0.55 }}
      />
      <span
        aria-hidden
        className="relative rounded-full"
        style={{ width: size * 0.6, height: size * 0.6, background: TONE_VAR[tone] }}
      />
    </span>
  ),
);
LivePulse.displayName = 'LivePulse';
