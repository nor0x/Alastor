import { api, errorText, type Command, type HostSummary } from './api';
import { liveUptime, uptime } from './format';
import { toast } from './toast.svelte';
import { confirm } from './ui/confirm.svelte';

/** Asks first, then has the agent reboot the host one minute later. Returns the queued command, or null if cancelled or refused. */
export async function rebootHost(h: HostSummary): Promise<Command | null> {
  const up = liveUptime(h);
  const ok = await confirm(
    `Reboot ${h.name}?`,
    `${h.rebootRequired ? 'A reboot is required to finish installing updates.\n\n' : ''}` +
      `The host reboots one minute after the agent picks this up${up !== null ? ` (up ${uptime(up)} now)` : ''}. ` +
      'Logged-in users are warned, and "sudo shutdown -c" on the host cancels it.\n\nIts services are unavailable until it is back.',
    { confirmLabel: 'Reboot', danger: true },
  );
  if (!ok) return null;
  try {
    const cmd = await api<Command>(`/api/hosts/${h.id}/actions/reboot`, { method: 'POST' });
    toast(`${h.name} reboots in about a minute.`);
    return cmd;
  } catch (e) {
    toast(errorText(e), 'error');
    return null;
  }
}
