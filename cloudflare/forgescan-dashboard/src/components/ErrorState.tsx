import { AlertTriangle, RefreshCw } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { Eyebrow } from '@/components/ui/eyebrow';

interface ErrorStateProps {
  title?: string;
  message: string;
  onRetry?: () => void;
  /** Optional fault code rendered in JetBrains Mono. */
  code?: string;
}

/**
 * Forge error state — no apology theater, no exclamation marks.
 * Severity-critical chip, terse copy, retry only when retryable.
 */
export function ErrorState({
  title = "We couldn't load this.",
  message,
  onRetry,
  code,
}: ErrorStateProps) {
  return (
    <Card className="border-severity-critical/40">
      <CardContent className="flex flex-col items-center justify-center py-12 text-center">
        <span
          className="flex h-12 w-12 items-center justify-center rounded-lg forge-sev-bg-critical"
          aria-hidden
        >
          <AlertTriangle className="h-6 w-6" strokeWidth={1.5} />
        </span>
        <Eyebrow variant="kicker" className="mt-4">
          Error
        </Eyebrow>
        <h2 className="mt-2 font-heading text-lg font-semibold text-foreground">
          {title}
        </h2>
        <p className="mt-2 max-w-md text-sm text-muted-foreground">{message}</p>
        {code && (
          <p className="mt-2 font-mono text-[11px] text-muted-foreground">
            Reference · <span className="text-foreground">{code}</span>
          </p>
        )}
        {onRetry && (
          <Button onClick={onRetry} variant="outline" className="mt-5">
            <RefreshCw className="mr-2 h-4 w-4" strokeWidth={1.5} />
            Retry
          </Button>
        )}
      </CardContent>
    </Card>
  );
}
