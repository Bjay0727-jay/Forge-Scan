import * as React from 'react';
import { Badge } from './badge';
import { cn } from '@/lib/utils';

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

/** Contractual order: Critical → High → Medium → Low → Info. */
export const SEVERITY_ORDER: readonly Severity[] = [
  'critical',
  'high',
  'medium',
  'low',
  'info',
] as const;

const LABEL: Record<Severity, string> = {
  critical: 'Critical',
  high:     'High',
  medium:   'Medium',
  low:      'Low',
  info:     'Info',
};

export interface SeverityBadgeProps extends React.HTMLAttributes<HTMLDivElement> {
  severity: Severity;
  /** Show the dot before the label. Useful in dense tables. */
  withDot?: boolean;
  /** Override the rendered label (defaults to capitalized severity name). */
  label?: string;
}

/**
 * Severity pill. Always uses the design-system severity tokens —
 * never substitute or invent new severity colors.
 */
export function SeverityBadge({
  severity,
  withDot = true,
  label,
  className,
  ...props
}: SeverityBadgeProps) {
  return (
    <Badge
      variant={severity}
      className={cn('uppercase tracking-wider text-[10px]', className)}
      {...props}
    >
      {withDot && (
        <span
          aria-hidden
          className="h-1.5 w-1.5 rounded-full"
          style={{ background: `var(--forge-sev-${severity})` }}
        />
      )}
      {label ?? LABEL[severity]}
    </Badge>
  );
}
SeverityBadge.displayName = 'SeverityBadge';
