import type { BanHour, EventStats, PosturePoint } from './api';
import { dayIso, shortDay, type Bucket, type Series } from './ui/chart';
import { shortTime } from './format';

// Turns /api/stats responses into chart inputs.

export function eventBuckets(stats: EventStats): Bucket[] {
  return stats.days.map((d) => ({
    key: d.day,
    label: shortDay(d.day),
    values: { critical: d.critical, high: d.high, medium: d.medium, low: d.low, info: d.info },
  }));
}

export const banSeries: Series[] = [
  { key: 'bans', label: 'Bans', color: 'var(--color-accent)' },
  { key: 'authFailures', label: 'Auth-failure reports', color: 'var(--color-accent-2)' },
];

export function banBuckets(hours: BanHour[]): Bucket[] {
  const multiDay = hours.length > 24;
  return hours.map((h) => ({
    key: h.at,
    label: multiDay ? `${new Date(h.at).toLocaleDateString(undefined, { weekday: 'short' })} ${shortTime(h.at)}` : shortTime(h.at),
    values: { bans: h.bans, authFailures: h.authFailures },
  }));
}

/** One measure as MetricChart points, skipping days where no host had reported it. */
export function trend(points: PosturePoint[], pick: (p: PosturePoint) => number | null): { at: string; value: number }[] {
  return points.flatMap((p) => {
    const v = pick(p);
    return v === null ? [] : [{ at: dayIso(p.day), value: v }];
  });
}

export const counts = (v: number) => new Intl.NumberFormat('en').format(Math.round(v));
