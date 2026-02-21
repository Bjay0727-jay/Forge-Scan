import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from 'recharts';
import { format, parseISO } from 'date-fns';
import type { RiskTrendPoint } from '@/types';

interface RiskTrendChartProps {
  data: RiskTrendPoint[];
}

export function RiskTrendChart({ data }: RiskTrendChartProps) {
  if (!data || data.length === 0) {
    return (
      <div className="flex h-full items-center justify-center text-muted-foreground">
        No trend data available
      </div>
    );
  }

  const formattedData = data.map((point) => ({
    ...point,
    date: format(parseISO(point.date), 'MMM d'),
  }));

  return (
    <ResponsiveContainer width="100%" height="100%">
      <LineChart
        data={formattedData}
        margin={{ top: 5, right: 30, left: 20, bottom: 5 }}
      >
        <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
        <XAxis
          dataKey="date"
          className="text-xs text-muted-foreground"
          tick={{ fill: 'hsl(var(--muted-foreground))' }}
        />
        <YAxis
          className="text-xs text-muted-foreground"
          tick={{ fill: 'hsl(var(--muted-foreground))' }}
        />
        <Tooltip
          contentStyle={{
            backgroundColor: 'hsl(var(--popover))',
            border: '1px solid hsl(var(--border))',
            borderRadius: '6px',
          }}
          labelStyle={{ color: 'hsl(var(--foreground))' }}
        />
        <Legend />
        <Line
          type="monotone"
          dataKey="risk_score"
          stroke="#14b8a6"
          strokeWidth={2}
          dot={false}
          name="Risk Score"
        />
        <Line
          type="monotone"
          dataKey="critical"
          stroke="#ef4444"
          strokeWidth={2}
          dot={false}
          name="Critical"
        />
        <Line
          type="monotone"
          dataKey="high"
          stroke="#f97316"
          strokeWidth={2}
          dot={false}
          name="High"
        />
        <Line
          type="monotone"
          dataKey="medium"
          stroke="#eab308"
          strokeWidth={2}
          dot={false}
          name="Medium"
        />
      </LineChart>
    </ResponsiveContainer>
  );
}
