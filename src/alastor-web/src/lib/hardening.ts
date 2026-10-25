/**
 * Lynis's index rewards every hardening step it knows about, so a fresh distribution install scores ~55-65 and few servers
 * reach 90. The tones are relative to that, not to the baseline score's 0-100.
 */
export function indexTone(index: number | null): 'ok' | 'warn' | 'bad' | 'muted' {
  if (index === null) return 'muted';
  return index >= 80 ? 'ok' : index >= 65 ? 'warn' : 'bad';
}

export interface LynisNote {
  text: string;
  /** Host tab or page that handles it, if any. */
  tab?: 'baseline' | 'updates' | 'vulnerabilities';
}

/**
 * Where a Lynis finding overlaps with something Alastor already does: a baseline mitigation, the updates tab, or a
 * suggestion that doesn't apply to hosts it manages. Keyed by Lynis test id.
 */
export const lynisNotes: Record<string, LynisNote> = {
  'DEB-0880': { text: 'Alastor configures fail2ban with its own jail.d drop-in, which is the recommended alternative to jail.local. Safe to accept on managed hosts.' },
  'FIRE-4590': { text: 'The baseline checks for an active firewall.', tab: 'baseline' },
  'KRNL-6000': { text: 'The baseline applies the most important kernel settings (ASLR, pointer leaks) as a managed sysctl drop-in.', tab: 'baseline' },
  'SSH-7408': { text: 'The baseline covers the SSH settings that matter most (root login, passwords, auth tries, grace time) with one-click fixes.', tab: 'baseline' },
  'PKGS-7392': { text: 'Pending updates are listed, and can be installed, on the Updates tab.', tab: 'updates' },
  'PKGS-7420': { text: 'Automatic security updates are a baseline check with a one-click fix.', tab: 'baseline' },
  'HRDN-7230': { text: 'Alastor can run ClamAV scans of web roots and uploads (opt-in, malware.scanSchedule); rootkit scanners are out of scope.' },
  'NETW-2705': { text: 'Often a container or a resolver that hides upstream servers (systemd-resolved lists only 127.0.0.53). Accept it if name resolution works.' },
};
