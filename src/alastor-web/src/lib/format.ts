const rtf = new Intl.RelativeTimeFormat('en', { numeric: 'auto', style: 'narrow' });
const units: [Intl.RelativeTimeFormatUnit, number][] = [
  ['year', 31_536_000],
  ['month', 2_592_000],
  ['week', 604_800],
  ['day', 86_400],
  ['hour', 3_600],
  ['minute', 60],
];

/** "5m ago", "in 12m", "yesterday". */
export function timeAgo(iso: string | null, now = Date.now()): string {
  if (!iso) return 'never';
  const seconds = Math.round((new Date(iso).getTime() - now) / 1000);
  for (const [unit, size] of units) {
    if (Math.abs(seconds) >= size) return rtf.format(Math.trunc(seconds / size), unit);
  }
  return 'just now';
}

export function fullDate(iso: string): string {
  return new Date(iso).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
}

export const number = new Intl.NumberFormat('en');

const bytesUnits = ['B', 'KB', 'MB', 'GB', 'TB'];
export function bytes(n: number): string {
  let i = 0;
  while (n >= 1024 && i < bytesUnits.length - 1) {
    n /= 1024;
    i++;
  }
  return `${n.toFixed(n >= 100 || i === 0 ? 0 : 1)} ${bytesUnits[i]}`;
}

export function uptime(seconds: number): string {
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  return d > 0 ? `${d}d ${h}h` : h > 0 ? `${h}h ${m}m` : `${m}m`;
}

/** Uptime now: the last reported value plus the time since that heartbeat. Null when offline or not reported yet. */
export function liveUptime(h: { isOnline: boolean; lastSeenAt: string | null; uptimeSeconds: number }, now = Date.now()): number | null {
  if (!h.isOnline || !h.lastSeenAt || !h.uptimeSeconds) return null;
  return h.uptimeSeconds + Math.max(0, (now - new Date(h.lastSeenAt).getTime()) / 1000);
}

export function shortTime(iso: string): string {
  return new Date(iso).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
}

/** "permanent" for a ban without expiry, else a relative time. */
export function expires(iso: string | null, now = Date.now()): string {
  return iso ? timeAgo(iso, now) : 'permanent';
}
