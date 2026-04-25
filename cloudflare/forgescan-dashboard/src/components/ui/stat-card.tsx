import * as React from 'react';
import type { LucideIcon } from 'lucide-react';
import { ArrowUpRight, ArrowDownRight, Minus } from 'lucide-react';
import { Card, CardContent } from './card';
import { cn } from '@/lib/utils';

export interface StatCardProps extends React.HTMLAttributes<HTMLDivElement> {
  /** Sora 600 caption above the value (e.g. "Open Findings"). */
  label: string;
  /** The hero number — Sora 700, formatted by caller. */
  value: React.ReactNode;
  /** Optional sub-stat (e.g. "vs. last 7 days"). */
  helper?: React.ReactNode;
  /** 32×32 teal-washed icon chip in the top-right. */
  icon?: LucideIcon;
  /** Trend chip below the value (positive = teal, negative = severity-low fade). */
  trend?: { direction: 'up' | 'down' | 'flat'; value: string };
  /** When true, animates the live-pulse dot beside the label. */
  live?: boolean;
}

/**
 * The canonical Forge stat card.
 *  - 16px internal padding (--forge-space-4)
 *  - Sora 28px / 700 hero number
 *  - 32×32 teal icon chip top-right
 *  - 1px navy border, --card surface, rounded-lg
 */
export const StatCard = React.forwardRef<HTMLDivElement, StatCardProps>(
  ({ label, value, helper, icon: Icon, trend, live, className, ...props }, ref) => (
    <Card
      ref={ref}
      role="group"
      aria-label={label}
      className={cn('forge-card-hover', className)}
      {...props}
    >
      <CardContent className="p-4">
        <div className="flex items-start justify-between gap-4">
          <div className="min-w-0">
            <div className="flex items-center gap-1.5">
              {live && (
                <span
                  aria-label="Live"
                  className="h-1.5 w-1.5 rounded-full bg-teal-400 forge-pulse-dot"
                />
              )}
              <p className="text-xs font-semibold uppercase tracking-[0.18em] text-muted-foreground">
                {label}
              </p>
            </div>
            <p className="mt-2 font-heading text-[28px] font-bold leading-none text-foreground">
              {value}
            </p>
            {trend && (
              <div
                className={cn(
                  'mt-2 inline-flex items-center gap-1 text-xs font-medium',
                  trend.direction === 'up'   && 'text-teal-400',
                  trend.direction === 'down' && 'text-severity-low',
                  trend.direction === 'flat' && 'text-muted-foreground',
                )}
              >
                {trend.direction === 'up'   && <ArrowUpRight   className="h-3 w-3" />}
                {trend.direction === 'down' && <ArrowDownRight className="h-3 w-3" />}
                {trend.direction === 'flat' && <Minus          className="h-3 w-3" />}
                {trend.value}
              </div>
            )}
            {helper && (
              <p className="mt-2 text-xs text-muted-foreground">{helper}</p>
            )}
          </div>
          {Icon && (
            <span className="forge-stat-chip shrink-0">
              <Icon className="h-4 w-4" strokeWidth={1.5} />
            </span>
          )}
        </div>
      </CardContent>
    </Card>
  ),
);
StatCard.displayName = 'StatCard';
