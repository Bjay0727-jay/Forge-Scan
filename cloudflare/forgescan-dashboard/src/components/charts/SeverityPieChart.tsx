import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip, Legend } from 'recharts';
import { getSeverityBgColor } from '@/lib/utils';
import type { Severity } from '@/types';

interface SeverityPieChartProps {
  data: Record<Severity, number>;
}

export function SeverityPieChart({ data }: SeverityPieChartProps) {
  const chartData = [
    { name: 'Critical', value: data.critical || 0, severity: 'critical' },
    { name: 'High', value: data.high || 0, severity: 'high' },
    { name: 'Medium', value: data.medium || 0, severity: 'medium' },
    { name: 'Low', value: data.low || 0, severity: 'low' },
    { name: 'Info', value: data.info || 0, severity: 'info' },
  ].filter((item) => item.value > 0);

  if (chartData.length === 0) {
    return (
      <div className="flex h-full items-center justify-center text-muted-foreground">
        No findings data available
      </div>
    );
  }

  return (
    <ResponsiveContainer width="100%" height="100%">
      <PieChart>
        <Pie
          data={chartData}
          cx="50%"
          cy="50%"
          innerRadius={60}
          outerRadius={100}
          paddingAngle={2}
          dataKey="value"
          label={({ name, percent }) =>
            `${name} ${(percent * 100).toFixed(0)}%`
          }
          labelLine={true}
        >
          {chartData.map((entry, index) => (
            <Cell
              key={`cell-${index}`}
              fill={getSeverityBgColor(entry.severity)}
            />
          ))}
        </Pie>
        <Tooltip
          formatter={(value: number) => [value, 'Findings']}
          contentStyle={{
            backgroundColor: 'hsl(var(--popover))',
            border: '1px solid hsl(var(--border))',
            borderRadius: '6px',
          }}
        />
        <Legend
          verticalAlign="bottom"
          height={36}
          formatter={(value, entry) => (
            <span className="text-sm text-foreground">{value}</span>
          )}
        />
      </PieChart>
    </ResponsiveContainer>
  );
}
