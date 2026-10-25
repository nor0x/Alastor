// Shared scale helpers for the hand-drawn SVG charts (MetricChart, StackedBars, Sparkline).

/** Rounds a maximum up to 1, 2, 2.5 or 5 × 10ⁿ so axis ticks land on clean numbers. */
export function niceMax(v: number): number {
  if (v <= 0) return 1;
  const mag = 10 ** Math.floor(Math.log10(v));
  for (const m of [1, 2, 2.5, 5, 10]) if (v <= m * mag) return m * mag;
  return 10 * mag;
}

/** 0 / 1.2K / 3.4M for axis ticks. */
export const compact = new Intl.NumberFormat('en', { notation: 'compact', maximumFractionDigits: 1 });

/** "Oct 25" in the browser's locale, for day buckets ("2026-10-25", no time zone shift). */
export function shortDay(day: string): string {
  const [y, m, d] = day.slice(0, 10).split('-').map(Number);
  return new Date(y, m - 1, d).toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
}

/** A day bucket as a local-midnight ISO string, so time-based charts place it on the right day. */
export function dayIso(day: string): string {
  const [y, m, d] = day.slice(0, 10).split('-').map(Number);
  return new Date(y, m - 1, d).toISOString();
}

/** Minutes east of UTC, as /api/stats/events expects. */
export const utcOffsetMinutes = () => -new Date().getTimezoneOffset();

/** One stacked series: `color` is a CSS colour, normally a var(--chart-…) token. */
export interface Series {
  key: string;
  label: string;
  color: string;
}

/** One column of a stacked bar chart. */
export interface Bucket {
  key: string;
  label: string;
  values: Record<string, number>;
}

/** Severity series for stacked event charts, most severe on the baseline. */
export const severitySeries: Series[] = [
  { key: 'critical', label: 'Critical', color: 'var(--chart-sev-critical)' },
  { key: 'high', label: 'High', color: 'var(--chart-sev-high)' },
  { key: 'medium', label: 'Medium', color: 'var(--chart-sev-medium)' },
  { key: 'low', label: 'Low', color: 'var(--chart-sev-low)' },
  { key: 'info', label: 'Info', color: 'var(--chart-sev-info)' },
];
