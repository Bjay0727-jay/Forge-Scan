import * as React from 'react';
import { cn } from '@/lib/utils';

export interface EyebrowProps extends React.HTMLAttributes<HTMLSpanElement> {
  /** Eyebrow uses 0.35em tracking (default); kicker is looser at 0.18em. */
  variant?: 'eyebrow' | 'kicker';
}

/**
 * The "FORGESCAN" / "FORGESOC" all-caps micro label that sits above logos
 * and section headings. Sora 600, teal-400, uppercase, eyebrow tracking.
 */
export const Eyebrow = React.forwardRef<HTMLSpanElement, EyebrowProps>(
  ({ className, variant = 'eyebrow', ...props }, ref) => (
    <span
      ref={ref}
      className={cn(
        variant === 'eyebrow' ? 'forge-eyebrow' : 'forge-kicker',
        className,
      )}
      {...props}
    />
  ),
);
Eyebrow.displayName = 'Eyebrow';
