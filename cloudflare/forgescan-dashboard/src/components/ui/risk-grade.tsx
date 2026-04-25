import * as React from 'react';
import { cn } from '@/lib/utils';

export type RiskGrade = 'A' | 'B' | 'C' | 'D' | 'F';

const GRADE_VAR: Record<RiskGrade, string> = {
  A: 'var(--forge-grade-a)',
  B: 'var(--forge-grade-b)',
  C: 'var(--forge-grade-c)',
  D: 'var(--forge-grade-d)',
  F: 'var(--forge-grade-f)',
};

const GRADE_LABEL: Record<RiskGrade, string> = {
  A: 'Excellent',
  B: 'Good',
  C: 'Fair',
  D: 'Poor',
  F: 'Critical',
};

export interface RiskGradeProps {
  /** Letter grade A–F. Maps to the contractual grade palette. */
  grade: RiskGrade;
  /** FRS score 0–100. Drives the surrounding ring. */
  score: number;
  /** Diameter in px. Default 96 — fits a stat card. */
  size?: number;
  /** Stroke width of the ring. Default 6. */
  stroke?: number;
  /** Optional aria-label override. */
  label?: string;
  className?: string;
}

/**
 * Executive Scorecard grade glyph.
 * Renders the letter grade in Sora 700 inside a partial-fill ring keyed
 * to the contractual A–F palette. Use only in scorecards — never as ornament.
 */
export const RiskGrade = React.forwardRef<HTMLDivElement, RiskGradeProps>(
  ({ grade, score, size = 96, stroke = 6, label, className }, ref) => {
    const clamped = Math.max(0, Math.min(100, Math.round(score)));
    const radius = (size - stroke) / 2;
    const circumference = 2 * Math.PI * radius;
    const offset = circumference - (clamped / 100) * circumference;
    const color = GRADE_VAR[grade];
    const aria = label ?? `Forge Risk Score ${clamped} of 100, grade ${grade} (${GRADE_LABEL[grade]})`;

    return (
      <div
        ref={ref}
        role="img"
        aria-label={aria}
        className={cn('relative inline-flex items-center justify-center', className)}
        style={{ width: size, height: size }}
      >
        <svg width={size} height={size} aria-hidden>
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            stroke="hsl(var(--border))"
            strokeWidth={stroke}
          />
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            stroke={color}
            strokeWidth={stroke}
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            strokeLinecap="round"
            transform={`rotate(-90 ${size / 2} ${size / 2})`}
            style={{ transition: 'stroke-dashoffset var(--forge-dur-slow) var(--forge-ease-out)' }}
          />
        </svg>
        <div
          className="absolute inset-0 flex flex-col items-center justify-center"
          style={{ color }}
        >
          <span className="font-heading font-bold leading-none" style={{ fontSize: size * 0.42 }}>
            {grade}
          </span>
          <span className="mt-1 font-mono text-[10px] tracking-wider text-muted-foreground">
            {clamped}/100
          </span>
        </div>
      </div>
    );
  },
);
RiskGrade.displayName = 'RiskGrade';
