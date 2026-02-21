import { XCircle, Check } from 'lucide-react';
import { Button } from '@/components/ui/button';

interface ConfirmBannerProps {
  title: string;
  description: string;
  confirmLabel?: string;
  cancelLabel?: string;
  onConfirm: () => void;
  onCancel: () => void;
  variant?: 'warning' | 'destructive';
}

export function ConfirmBanner({
  title,
  description,
  confirmLabel = 'Confirm',
  cancelLabel = 'Cancel',
  onConfirm,
  onCancel,
  variant = 'warning',
}: ConfirmBannerProps) {
  const isDestructive = variant === 'destructive';

  return (
    <div
      className={`mb-4 rounded-lg border p-4 ${
        isDestructive
          ? 'border-red-500/30 bg-red-500/10'
          : 'border-amber-500/30 bg-amber-500/10'
      }`}
    >
      <div className="flex items-center justify-between">
        <div>
          <p
            className={`font-semibold text-sm ${
              isDestructive ? 'text-red-300' : 'text-amber-300'
            }`}
          >
            {title}
          </p>
          <p className="text-sm text-muted-foreground mt-1">{description}</p>
        </div>
        <div className="flex items-center gap-2 ml-4 flex-shrink-0">
          <Button size="sm" variant="outline" onClick={onCancel} className="gap-1.5">
            <XCircle className="h-4 w-4" /> {cancelLabel}
          </Button>
          <Button
            size="sm"
            onClick={onConfirm}
            className="gap-1.5"
            style={{
              background: isDestructive ? '#dc2626' : '#14b8a6',
            }}
          >
            <Check className="h-4 w-4" /> {confirmLabel}
          </Button>
        </div>
      </div>
    </div>
  );
}
