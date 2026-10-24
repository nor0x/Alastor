// Thin fetch wrapper for the SentinelVPS REST API (cookie session; see docs/architecture.md §3).

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

let onUnauthorized: (() => void) | undefined;

/** Called when any request comes back 401, so the app can show the login form. */
export function setUnauthorizedHandler(handler: () => void) {
  onUnauthorized = handler;
}

export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  // Cookie-authenticated writes must carry the CSRF header.
  if (init.method && init.method !== 'GET') headers.set('X-Sentinel-Request', '1');
  if (init.body && !headers.has('content-type')) headers.set('content-type', 'application/json');
  const res = await fetch(path, { ...init, headers, credentials: 'same-origin' });
  if (res.status === 401 && !path.startsWith('/api/auth/login')) onUnauthorized?.();
  if (!res.ok) {
    let message = res.statusText || `HTTP ${res.status}`;
    try {
      const problem = await res.json();
      message = problem.detail ?? problem.title ?? message;
    } catch {
      /* not JSON */
    }
    throw new ApiError(res.status, message);
  }
  return (res.status === 204 ? undefined : await res.json()) as T;
}

export type Severity = 'Info' | 'Low' | 'Medium' | 'High' | 'Critical';
export const severities: Severity[] = ['Critical', 'High', 'Medium', 'Low', 'Info'];

export interface Me {
  username: string;
  role: string;
  readOnly: boolean;
}

export interface FeedItem {
  id: string;
  source: string;
  sourceName: string;
  type: 'cve' | 'news';
  title: string;
  url: string;
  publishedAt: string;
  summary: string;
  severity: Severity | null;
  cvssScore: number | null;
  exploited: boolean;
  tags: string[];
  products: string[];
}

export interface FeedPage {
  items: FeedItem[];
  total: number;
  page: number;
  pageSize: number;
}

export interface FeedSource {
  id: string;
  name: string;
  kind: 'nvd' | 'kev' | 'rss';
  homepage: string;
  lastSuccessAt: string | null;
  lastAttemptAt: string | null;
  nextAttemptAt: string | null;
  consecutiveFailures: number;
  lastError: string | null;
  items: number;
}

export interface TagCount {
  tag: string;
  count: number;
}
