import { api, type UpdateStatus } from './api';

// The newest release the server has seen on GitHub, for the sidebar notice. The server checks twice a day; dismissing
// hides one release in this browser, and the next release shows again.

const dismissedKey = 'alastor.update.dismissed';

function readDismissed(): string | null {
  try { return localStorage.getItem(dismissedKey); } catch { return null; }
}

export const update = $state<{ status: UpdateStatus | null; dismissed: string | null }>({ status: null, dismissed: readDismissed() });

/** An available release the user hasn't dismissed. */
export function pendingUpdate(): UpdateStatus | null {
  const s = update.status;
  return s?.available && s.latest && s.url && s.latest !== update.dismissed ? s : null;
}

export async function refreshUpdate() {
  update.status = await api<UpdateStatus>('/api/about/update').catch(() => update.status);
}

export function dismissUpdate() {
  const tag = update.status?.latest;
  if (!tag) return;
  update.dismissed = tag;
  try { localStorage.setItem(dismissedKey, tag); } catch { /* storage blocked: hidden until reload */ }
}

let wired = false;
export function wireUpdate() {
  if (wired) return;
  wired = true;
  setInterval(() => void refreshUpdate(), 3_600_000);
}
