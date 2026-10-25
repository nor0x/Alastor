<script lang="ts">
  import { api, errorText, type Command, type HostNetwork } from './api';
  import { setLayerKey } from './baseline';
  import { on, refreshOn } from './live.svelte';
  import { exposureLook, firewallLabels } from './network';
  import { canWrite } from './session.svelte';
  import { toast } from './toast.svelte';
  import { confirm } from './ui/confirm.svelte';
  import CopyButton from './ui/CopyButton.svelte';
  import Time from './ui/Time.svelte';

  let { hostId, isOnline }: { hostId: string; isOnline: boolean } = $props();

  let data = $state<HostNetwork | null>(null);
  let error = $state('');
  let checking = $state(false);

  async function load() {
    try {
      const prev = data?.lastAttemptAt;
      data = await api<HostNetwork>(`/api/hosts/${hostId}/network`);
      error = '';
      if (checking && data.lastAttemptAt !== prev) checking = false;
    } catch (e) {
      error = errorText(e);
    }
  }

  $effect(() => {
    void hostId;
    load();
    const offs = [
      on('hostUpdated', (h: { id: string }) => { if (h.id === hostId) load(); }),
      refreshOn(['policyChanged'], load, 60_000),
    ];
    return () => offs.forEach((o) => o());
  });

  const report = $derived(data?.report ?? null);
  const exposure = $derived(data?.exposure ?? null);
  const look = $derived(exposureLook(exposure?.level ?? null, exposure?.accepted));
  const exposed = $derived(!!exposure && !exposure.accepted && (exposure.level === 'Public' || exposure.level === 'PossiblyPublic'));
  const ts = $derived(report?.tailscale ?? null);
  const port = $derived(report?.ssh?.ports[0] ?? 22);
  const usesUfw = $derived(report?.firewall.tool === 'ufw' || report?.firewall.tool === null);
  const keyDays = $derived(ts?.keyExpiry ? Math.floor((new Date(ts.keyExpiry).getTime() - Date.now()) / 86_400_000) : null);

  /** Commands that close the exposure: the tailnet when Tailscale is up, else one admin address. */
  const fixCommands = $derived.by(() => {
    if (!usesUfw) return [];
    const rules = ts?.running
      ? [`sudo ufw allow in on tailscale0 to any port ${port} proto tcp`]
      : [`sudo ufw allow from YOUR.ADMIN.IP to any port ${port} proto tcp`];
    return [
      ...rules,
      `sudo ufw delete allow ${port === 22 ? 'OpenSSH' : `${port}/tcp`}   # and any other rule that opens ${port} to anywhere`,
      'sudo ufw enable',
    ];
  });

  async function check() {
    try {
      await api<Command>(`/api/hosts/${hostId}/actions/check-network`, { method: 'POST' });
      checking = true;
      toast(isOnline ? 'Check queued; it takes a second.' : 'The host is offline; it checks when the agent reconnects.');
      setTimeout(() => (checking = false), 5 * 60_000);
    } catch (e) {
      toast(errorText(e), 'error');
    }
  }

  async function setAccepted(value: boolean) {
    if (value) {
      const ok = await confirm('Accept public SSH on this host?',
        'For a bastion or a host with no other way in. It stays listed as public, but no longer counts as a problem or raises alerts. Sets network.allowPublicSsh on this host.',
        { confirmLabel: 'Accept' });
      if (!ok) return;
    }
    try {
      await setLayerKey({ scope: 'host', id: hostId }, ['network', 'allowPublicSsh'], value ? true : undefined,
        value ? 'Network: accept public SSH' : 'Network: stop accepting public SSH');
      toast(value ? 'Accepted for this host.' : 'Public SSH counts as a problem again on this host.');
    } catch (e) {
      toast(errorText(e), 'error');
    }
  }
</script>

{#if error && !data}
  <div class="banner bad" role="alert"><p>Couldn't load the network check: {error}</p></div>
{:else if !data}
  <div class="skeleton-block"></div>
{:else}
  <div class="stack">
    <section class="card summary">
      <div class="figure">
        <span class="label">SSH from the internet</span>
        <span class="pill big-pill {look.tone}">{look.label}</span>
      </div>
      {#if report?.ssh}
        <div class="facts">
          <span>port <strong>{report.ssh.ports.join(', ')}</strong></span>
          <span>passwords <strong class:bad-text={report.ssh.passwordAuthentication}>{report.ssh.passwordAuthentication ? 'allowed' : 'off'}</strong></span>
          <span>root login <strong>{report.ssh.permitRootLogin}</strong></span>
          <span>firewall <strong>{report.firewall.tool ?? '—'}</strong> <span class="muted">{firewallLabels[report.firewall.verdict]}</span></span>
        </div>
      {/if}
      <div class="meta">
        <span class="muted small">{#if data.checkedAt}checked <Time iso={data.checkedAt} />{:else}not checked yet{/if}</span>
        {#if canWrite()}<button class="btn small" onclick={check} disabled={checking}>{checking ? 'Checking…' : 'Check now'}</button>{/if}
      </div>
    </section>

    {#if data.lastCheckSucceeded === false}
      <div class="banner bad" role="alert">
        <p><strong>The last check failed</strong>{#if data.lastAttemptAt} (<Time iso={data.lastAttemptAt} />){/if}: <span class="mono small">{data.lastCheckError}</span></p>
      </div>
    {/if}

    {#if exposure}
      <section class="card pad stack-sm" class:alert={exposed}>
        <h2>{exposed ? 'SSH is reachable from the internet' : 'Why'}</h2>
        <ul class="reasons">
          {#each exposure.reasons as r, i (i)}<li>{r}</li>{/each}
        </ul>
        {#if exposed}
          <p>
            Every server on the internet gets SSH password guessing around the clock. fail2ban bans the guessers and key-only logins make
            guessing pointless{report?.ssh?.passwordAuthentication ? ' (password logins are on here: turn them off on the Baseline tab)' : ''}, but the
            safest SSH port is one nobody can reach.
            {ts?.running ? 'Tailscale is up on this host, so you can limit SSH to the tailnet:' : 'Limit it to the addresses you administer from, or put the host on a private network such as Tailscale:'}
          </p>
          {#if fixCommands.length}
            <div class="commands">
              {#each fixCommands as cmd, i (i)}<div class="cmd"><code>{cmd}</code><CopyButton text={cmd.replace(/\s+#.*$/, '')} /></div>{/each}
            </div>
          {:else}
            <p class="small muted">This host uses {report?.firewall.tool}; add a rule that accepts port {port} only {ts?.running ? 'on tailscale0' : 'from your admin addresses'} and drops it otherwise.</p>
          {/if}
          {#if ts?.running && !ts.sshEnabled}<p class="small">Or let Tailscale handle SSH itself, with tailnet identities instead of keys: <code>sudo tailscale set --ssh</code>.</p>{/if}
          <p class="small note">Before closing the port, make sure the new way in works (open a second session over it) and that you have your provider's console as a fallback.</p>
          {#if !ts}<p class="small"><a href="https://tailscale.com/download/linux" target="_blank" rel="noreferrer">Install Tailscale</a> from its package repository; the agent detects it on the next check.</p>{/if}
        {/if}
        {#if canWrite() && (exposure.level === 'Public' || exposure.level === 'PossiblyPublic')}
          <div>
            {#if data.allowPublicSsh}<button class="btn ghost small" onclick={() => setAccepted(false)}>Stop accepting public SSH</button>
            {:else}<button class="btn ghost small" onclick={() => setAccepted(true)}>Accept: public SSH is intended here</button>{/if}
          </div>
        {/if}
      </section>
    {/if}

    <section class="card pad stack-sm">
      <h2>Tailscale</h2>
      {#if !report}
        <p class="muted">Not checked yet.</p>
      {:else if !ts}
        <p>
          Not installed. <a href="https://tailscale.com/" target="_blank" rel="noreferrer">Tailscale</a> is optional: it puts your servers and
          laptops on a private WireGuard network, so SSH and admin ports don't need to face the internet. It comes from Tailscale's own
          package repository; joining a tailnet needs your login, so SentinelVPS never installs it.
          <a href="https://tailscale.com/download/linux" target="_blank" rel="noreferrer">Install instructions</a>.
        </p>
      {:else}
        <dl class="kv">
          <dt>State</dt>
          <dd>
            {#if ts.running}<span class="pill ok">✓ connected</span>
            {:else if ts.backendState === 'NeedsLogin'}<span class="pill warn">needs login</span> <span class="small muted">run <code>sudo tailscale up</code></span>
            {:else if ts.backendState === 'NotRunning'}<span class="pill warn">tailscaled not running</span> <span class="small muted">{report.tailscaleError}</span>
            {:else}<span class="pill muted">{ts.backendState}</span>{/if}
          </dd>
          {#if ts.tailnet}<dt>Tailnet</dt><dd>{ts.tailnet}</dd>{/if}
          {#if ts.ips.length}<dt>Addresses</dt><dd class="mono small">{ts.ips.join(' · ')}{#if ts.dnsName}<br />{ts.dnsName}{/if}</dd>{/if}
          {#if ts.running}<dt>Peers</dt><dd>{ts.peersOnline} of {ts.peersTotal} online</dd>{/if}
          {#if ts.sshEnabled !== null}<dt>Tailscale SSH</dt><dd>{ts.sshEnabled ? 'on' : 'off'}</dd>{/if}
          {#if ts.keyExpiry}
            <dt>Key expiry</dt>
            <dd class:bad-text={keyDays !== null && keyDays < 14}><Time iso={ts.keyExpiry} />{keyDays !== null && keyDays < 14 ? ' · re-authenticate, or disable key expiry for this server in the Tailscale admin console' : ''}</dd>
          {/if}
          {#if ts.version}<dt>Version</dt><dd class="mono small">{ts.version.split('-')[0]}</dd>{/if}
        </dl>
        {#if ts.health.length && !ts.running}<p class="small muted">{ts.health.join(' ')}</p>{/if}
        {#if ts.running && !data.tailnetAllowlisted}
          <p class="small note">The ban allowlist doesn't include the tailnet. Add <code>100.64.0.0/10</code> on the <a href="/bans">Bans page</a> so fail2ban never bans your own devices.</p>
        {/if}
      {/if}
    </section>

    {#if report}
      <section class="card">
        <header><h2>Addresses</h2><span class="hint">{#if data.observedAddress}the server sees this host as <span class="mono">{data.observedAddress}</span>{/if}</span></header>
        <div class="table-wrap">
          <table class="table">
            <thead><tr><th>Interface</th><th>Address</th><th>Kind</th><th>SSH</th></tr></thead>
            <tbody>
              {#each report.addresses.filter((a) => a.kind !== 'Loopback' && a.kind !== 'LinkLocal') as a (a.interface + a.address)}
                <tr>
                  <td class="mono small">{a.interface}</td>
                  <td class="mono small">{a.address}/{a.prefixLength}</td>
                  <td><span class="pill {a.kind === 'Public' ? 'warn' : a.kind === 'Tailnet' ? 'info' : 'muted'}">{a.kind.toLowerCase()}</span></td>
                  <td class="small">{exposure?.reachableOn.includes(a.address) ? `listens (${report.ssh?.ports.join(', ')})` : '—'}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      </section>

      <section class="card pad stack-sm">
        <h2 class="h-sm">Check settings</h2>
        <p class="muted small">
          Schedule <code>{data.schedule.value}</code>{data.schedule.isDefault ? ' (default)' : ''}. The agent reads sshd's ports (<code>sshd -T</code>),
          its listening sockets, the host's addresses and the ufw or nftables rules, and changes nothing. It can't see your provider's firewall or
          security groups. New public exposure raises an alert (High when passwords are allowed).
        </p>
        <p class="small"><a href="/policies/host/{hostId}">Change for this host</a> · <a href="/policies/global">for all hosts</a></p>
      </section>
    {/if}
  </div>
{/if}

<style>
  .summary { display: flex; flex-wrap: wrap; align-items: center; gap: 16px 32px; padding: 16px; }
  .figure { display: flex; flex-direction: column; gap: 6px; }
  .label { font-size: 12px; color: var(--muted); }
  .big-pill { font-size: 15px; padding: 4px 10px; }
  .facts { display: flex; flex-wrap: wrap; gap: 6px 18px; color: var(--muted); }
  .facts strong { color: var(--text-strong); }
  .facts strong.bad-text, .bad-text { color: var(--bad); }
  .meta { margin-left: auto; display: flex; flex-wrap: wrap; align-items: center; gap: 10px; }
  .pad { padding: 14px 16px 16px; }
  .stack-sm { display: flex; flex-direction: column; gap: 8px; }
  .stack-sm p, .stack-sm h2 { margin: 0; }
  .h-sm { font-size: 14px; }
  .alert { border-color: color-mix(in srgb, var(--bad) 55%, var(--border)); }
  .reasons { margin: 0; padding-left: 18px; display: flex; flex-direction: column; gap: 3px; }
  .note { color: var(--warn); }
  .commands { display: flex; flex-direction: column; gap: 6px; }
  .cmd { display: flex; align-items: flex-start; gap: 8px; }
  .cmd code { flex: 1; min-width: 0; padding: 6px 8px; border-radius: 6px; background: var(--surface-2); font-size: 12px; overflow-wrap: anywhere; white-space: pre-wrap; }
  .kv { display: grid; grid-template-columns: max-content 1fr; gap: 6px 16px; margin: 0; }
  .kv dt { color: var(--muted); }
  .kv dd { margin: 0; overflow-wrap: anywhere; }
  @media (max-width: 640px) {
    .meta { margin-left: 0; }
  }
</style>
