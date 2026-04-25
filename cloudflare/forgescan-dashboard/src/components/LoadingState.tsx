import { Loader2 } from 'lucide-react';
import { Card, CardContent } from '@/components/ui/card';

interface LoadingStateProps {
  /** Replace the default "Loading …" text. Keep terse. */
  message?: string;
  /** Inline mode renders without the Card chrome — useful inside tables/cards. */
  inline?: boolean;
}

/**
 * Forge loading state — teal spinner, no skeleton copy.
 * Spec: "Loading …" with a teal spinner — never a skeleton with copy.
 */
export function LoadingState({ message = 'Loading …', inline }: LoadingStateProps) {
  const body = (
    <div
      role="status"
      aria-live="polite"
      className="flex flex-col items-center justify-center gap-3 py-10 text-muted-foreground"
    >
      <Loader2
        className="h-8 w-8 animate-spin text-teal-400"
        strokeWidth={1.5}
        aria-hidden
      />
      <p className="text-sm">{message}</p>
    </div>
  );

  if (inline) return body;

  return (
    <Card>
      <CardContent>{body}</CardContent>
    </Card>
  );
}
