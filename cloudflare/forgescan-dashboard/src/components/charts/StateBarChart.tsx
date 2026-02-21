import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from 'recharts';
import type { FindingState } from '@/types';

interface StateBarChartProps {
  data: Record<FindingState, number>;
}

export function StateBarChart({ data }: StateBarChartProps) {
  const chartData = [
    { name: 'Open', value: data.open || 0, fill: '#ef4444' },
    { name: 'Acknowledged', value: data.acknowledged || 0, fill: '#eab308' },
    { name: 'Resolved', value: data.resolved || 0, fill: '#22c55e' },
    { name: 'False Positive', value: data.false_positive || 0, fill: '#6b7280' },
  ];

  const total = chartData.reduce((sum, item) => sum + item.value, 0);

  if (total === 0) {
    return (
      <div className="flex h-full items-center justify-center text-muted-foreground">
        No findings data available
      </div>
    );
  }

  return (
    <ResponsiveContainer width="100%" height="100%">
      <BarChart
        data={chartData}
        layout="vertical"
        margin={{ top: 5, right: 30, left: 80, bottom: 5 }}
      >
        <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
        <XAxis
          type="number"
          className="text-xs text-muted-foreground"
          tick={{ fill: 'hsl(var(--muted-foreground))' }}
        />
        <YAxis
          type="category"
          dataKey="name"
          className="text-xs text-muted-foreground"
          tick={{ fill: 'hsl(var(--muted-foreground))' }}
        />
        <Tooltip
          contentStyle={{
            backgroundColor: 'hsl(var(--popover))',
            border: '1px solid hsl(var(--border))',
            borderRadius: '6px',
          }}
          formatter={(value: number) => [value, 'Findings']}
        />
        <Bar dataKey="value" radius={[0, 4, 4, 0]} />
      </BarChart>
    </ResponsiveContainer>
  );
}
