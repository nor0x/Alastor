export interface Toast {
  id: number;
  kind: 'ok' | 'error' | 'info';
  text: string;
}

export const toasts = $state<Toast[]>([]);
let next = 1;

export function toast(text: string, kind: Toast['kind'] = 'ok', ms = 4500) {
  const id = next++;
  toasts.push({ id, kind, text });
  setTimeout(() => dismiss(id), kind === 'error' ? ms * 2 : ms);
}

export function dismiss(id: number) {
  const i = toasts.findIndex((t) => t.id === id);
  if (i >= 0) toasts.splice(i, 1);
}
