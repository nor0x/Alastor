import type { Me } from './api';

export const session = $state<{ me: Me | null }>({ me: null });

/** True when the signed-in principal may change things (API-key readers may not). */
export function canWrite(): boolean {
  return !!session.me && !session.me.readOnly;
}
