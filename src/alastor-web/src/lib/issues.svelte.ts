import { api, type IssueSummary } from './api';
import { on, refreshOn } from './live.svelte';

// Open-issue counts for the navigation badge, shared app-wide and refreshed on issuesChanged hints.

export const issues = $state<{ summary: IssueSummary | null }>({ summary: null });

export async function refreshIssues() {
  issues.summary = await api<IssueSummary>('/api/issues/summary').catch(() => issues.summary);
}

let wired = false;
export function wireIssues() {
  if (wired) return;
  wired = true;
  on('issuesChanged', () => void refreshIssues());
  refreshOn([], () => void refreshIssues(), 60_000); // polling fallback while the hub is down
}
