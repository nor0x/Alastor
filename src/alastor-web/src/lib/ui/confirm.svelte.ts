// A promise-based confirm dialog, rendered once by <ConfirmHost /> in App.svelte.

export interface ConfirmRequest {
  title: string;
  message: string;
  confirmLabel?: string;
  danger?: boolean;
  resolve: (ok: boolean) => void;
}

export const pendingConfirm = $state<{ current: ConfirmRequest | null }>({ current: null });

export function confirm(title: string, message: string, opts: { confirmLabel?: string; danger?: boolean } = {}): Promise<boolean> {
  pendingConfirm.current?.resolve(false);
  return new Promise((resolve) => (pendingConfirm.current = { title, message, ...opts, resolve }));
}
