import type { SshExposureLevel } from './api';

export interface ExposureLook {
  label: string;
  tone: 'ok' | 'warn' | 'bad' | 'muted' | 'info';
}

/** The pill for an exposure level. Icon + text, so colour is never the only signal. */
export function exposureLook(level: SshExposureLevel | null, accepted = false): ExposureLook {
  if (level === null) return { label: 'not checked', tone: 'muted' };
  if (accepted && (level === 'Public' || level === 'PossiblyPublic')) return { label: 'public, accepted', tone: 'muted' };
  switch (level) {
    case 'Public': return { label: 'public', tone: 'bad' };
    case 'PossiblyPublic': return { label: 'possibly public', tone: 'warn' };
    case 'Restricted': return { label: 'restricted', tone: 'ok' };
    case 'PrivateOnly': return { label: 'private network', tone: 'ok' };
    case 'TailnetOnly': return { label: 'tailnet only', tone: 'ok' };
    case 'LocalOnly': return { label: 'local only', tone: 'ok' };
    case 'NotListening': return { label: 'not listening', tone: 'muted' };
    case 'NoSsh': return { label: 'no SSH server', tone: 'muted' };
    default: return { label: 'unknown', tone: 'muted' };
  }
}

export const firewallLabels: Record<string, string> = {
  NoFirewall: 'no firewall',
  OpenToAnywhere: 'allows SSH from anywhere',
  Restricted: 'restricts SSH',
  Blocked: 'blocks SSH',
  Unknown: 'unknown',
};

export function isExposed(level: SshExposureLevel | null, accepted: boolean): boolean {
  return !accepted && (level === 'Public' || level === 'PossiblyPublic');
}
