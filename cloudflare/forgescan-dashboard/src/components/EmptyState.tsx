import type { LucideIcon } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { Eyebrow } from '@/components/ui/eyebrow';

interface EmptyStateProps {
  icon: LucideIcon;
  /** Eyebrow above the title — short, all-caps. e.g. "FINDINGS". */
  eyebrow?: string;
  title: string;
  description: string;
  actionLabel?: string;
  onAction?: () => void;
  /** Secondary CTA, ghost-styled. */
  secondaryActionLabel?: string;
  onSecondaryAction?: () => void;
}

/**
 * Forge empty state — terse, operator-first, no apology theater.
 * Uses the canonical 32px teal icon chip and Sora 600 title.
 */
export function EmptyState({
  icon: Icon,
  eyebrow,
  title,
  description,
  actionLabel,
  onAction,
  secondaryActionLabel,
  onSecondaryAction,
}: EmptyStateProps) {
  return (
    <Card>
      <CardContent className="flex flex-col items-center justify-center py-12 text-center">
        <span className="forge-stat-chip h-12 w-12 rounded-lg" aria-hidden>
          <Icon className="h-6 w-6" strokeWidth={1.5} />
        </span>
        {eyebrow && <Eyebrow className="mt-4">{eyebrow}</Eyebrow>}
        <h2 className="mt-2 font-heading text-lg font-semibold text-foreground">
          {title}
        </h2>
        <p className="mt-2 max-w-md text-sm text-muted-foreground">{description}</p>
        {(actionLabel || secondaryActionLabel) && (
          <div className="mt-5 flex flex-wrap items-center justify-center gap-2">
            {actionLabel && onAction && (
              <Button onClick={onAction}>{actionLabel}</Button>
            )}
            {secondaryActionLabel && onSecondaryAction && (
              <Button variant="ghost" onClick={onSecondaryAction}>
                {secondaryActionLabel}
              </Button>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
