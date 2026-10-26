<script lang="ts">
  import { untrack } from 'svelte';
  import { api, errorText, type Command, type HostNetwork } from './api';
  import { setLayerKey } from './baseline';
  import { on, refreshOn } from './live.svelte';
  import { exposureLook, firewallLabels } from './network';
  import { canWrite } from './session.svelte';
  import { toast } from './toast.svelte';
  import { confirm } from './ui/confirm.svelte';
  import CopyButton from './ui/CopyButton.svelte';
  import Icon from './ui/Icon.svelte';
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
    // load() reads `data` before its first await; untracked, so a response doesn't re-run this effect.
    untrack(load);
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
      <div class="lead">
        <span class="figure-label">SSH from the internet</span>
        <span class="figure-value status {look.tone}">
          {#if look.tone === 'bad' || look.tone === 'warn'}<Icon name="alert" size={20} />{:else if look.tone === 'ok'}<Icon name="check" size={20} />{/if}
          {look.label}
        </span>
      </div>
      <div class="counts">
        {#if report?.ssh}
          <span class="pair">port <strong class="n">{report.ssh.ports.join(', ')}</strong></span>
          <span class="pair">passwords <strong class="n" class:bad={report.ssh.passwordAuthentication}>{report.ssh.passwordAuthentication ? 'allowed' : 'off'}</strong></span>
          <span class="pair">root login <strong class="n">{report.ssh.permitRootLogin}</strong></span>
          <span class="pair">firewall <strong class="n">{#if report.firewall.tool}{report.firewall.tool}{:else}<span class="nil" aria-label="none"></span>{/if}</strong> <span>{firewallLabels[report.firewall.verdict]}</span></span>
        {/if}
      </div>
      <div class="meta">
        <span class="meta-facts">{#if data.checkedAt}<span>Checked <Time iso={data.checkedAt} /></span>{:else}<span>Not checked yet</span>{/if}</span>
        <span class="keys">{#if canWrite()}<button class="btn small" onclick={check} disabled={checking}>{checking ? 'Checking…' : 'Check now'}</button>{/if}</span>
      </div>
    </section>

    {#if data.lastCheckSucceeded === false}
      <div class="banner bad" role="alert">
        <Icon name="error" />
        <p><strong>The last check failed</strong>{#if data.lastAttemptAt} (<Time iso={data.lastAttemptAt} />){/if}: <span class="mono small">{data.lastCheckError}</span></p>
      </div>
    {/if}

    {#if exposure}
      <section class="card pad stack-sm" class:alert={exposed}>
        <h2>{#if exposed}<Icon name="alert" />{/if}{exposed ? 'SSH is reachable from the internet' : 'Why'}</h2>
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
          package repository; joining a tailnet needs your login, so Alastor never installs it.
          <a href="https://tailscale.com/download/linux" target="_blank" rel="noreferrer">Install instructions</a>.
        </p>
      {:else}
        <dl class="kv">
          <dt>State</dt>
          <dd class="state">
            {#if ts.running}<span class="pill ok">connected</span>
            {:else if ts.backendState === 'NeedsLogin'}<span class="pill warn">needs login</span> <span class="small muted">run <code>sudo tailscale up</code></span>
            {:else if ts.backendState === 'NotRunning'}<span class="pill warn">tailscaled not running</span> <span class="small muted">{report.tailscaleError}</span>
            {:else}<span class="pill muted">{ts.backendState}</span>{/if}
          </dd>
          {#if ts.tailnet}<dt>Tailnet</dt><dd>{ts.tailnet}</dd>{/if}
          {#if ts.ips.length}<dt>Addresses</dt><dd class="mono small"><span class="ips">{#each ts.ips as ip, i (i)}<span>{ip}</span>{/each}</span>{#if ts.dnsName}<span class="dns">{ts.dnsName}</span>{/if}</dd>{/if}
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
        <header class="addr-head"><h2>Addresses</h2><span class="hint">{#if data.observedAddress}the server sees this host as <span class="mono">{data.observedAddress}</span>{/if}</span></header>
        <div class="table-wrap">
          <table class="table">
            <thead><tr><th>Interface</th><th>Address</th><th>Kind</th><th>SSH</th></tr></thead>
            <tbody>
              {#each report.addresses.filter((a) => a.kind !== 'Loopback' && a.kind !== 'LinkLocal') as a (a.interface + a.address)}
                <tr>
                  <td class="mono small">{a.interface}</td>
                  <td class="mono small">{a.address}/{a.prefixLength}</td>
                  <td><span class="pill {a.kind === 'Public' ? 'warn' : a.kind === 'Tailnet' ? 'info' : 'muted'}">{a.kind.toLowerCase()}</span></td>
                  <td class="small">{#if exposure?.reachableOn.includes(a.address)}listens ({report.ssh?.ports.join(', ')}){:else}<span class="nil" aria-label="none"></span>{/if}</td>
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
        <p class="small links"><a href="/policies/host/{hostId}">Change for this host</a><a href="/policies/global">for all hosts</a></p>
      </section>
    {/if}
  </div>
{/if}

<style>
  /* The summary ledger, the same strip on every host tab: lead figure | counts | when + keys, parted by hairlines. */
  .summary { display: grid; grid-template-columns: minmax(200px, max-content) minmax(0, 1fr) minmax(0, max-content); overflow: hidden; }
  .summary > * { display: flex; flex-direction: column; justify-content: center; gap: var(--space-2xs); min-width: 0; padding: var(--space-md); }
  .summary > * + * { box-shadow: inset 1px 0 0 var(--border); }
  .lead .figure-value { display: inline-flex; align-items: baseline; }
  .counts { flex-direction: row; flex-wrap: wrap; align-items: center; align-content: center; justify-content: flex-start; gap: var(--space-xs) var(--space-lg); color: var(--muted); }
  .pair { display: inline-flex; align-items: baseline; gap: var(--space-2xs); color: var(--muted); }
  .pair .n { font-family: var(--font-display); font-weight: 600; font-size: var(--text-lg); line-height: 1; color: var(--text-strong); font-variant-numeric: tabular-nums; }
  .pair .n.bad { color: var(--bad); }
  .meta { align-items: flex-end; text-align: right; }
  .meta-facts { display: flex; flex-direction: column; align-items: inherit; gap: var(--space-3xs); font-size: var(--text-sm); color: var(--muted); }
  .keys { display: flex; flex-wrap: wrap; justify-content: flex-end; gap: var(--space-xs); margin-top: var(--space-2xs); }
  .keys:empty { display: none; }
  @media (max-width: 760px) {
    .summary { grid-template-columns: minmax(0, 1fr); }
    .summary > * + * { box-shadow: inset 0 1px 0 var(--border); }
    .counts:empty { display: none; }
    .meta { align-items: flex-start; text-align: left; }
    .keys { justify-content: flex-start; }
  }
  /* The lead here is a state, not a number: a figure set a step smaller, one icon by tone. */
  .lead .figure-value.status { align-items: center; gap: var(--space-xs); font-size: var(--text-2xl); }
  .figure-value.muted { color: var(--muted); }
  .pair .n { font-size: var(--text-md); }

  .pad { padding: var(--space-md); }
  .stack-sm { display: flex; flex-direction: column; gap: var(--space-xs); }
  .stack-sm p, .stack-sm h2 { margin: 0; }
  .stack-sm h2 { display: flex; align-items: center; gap: var(--space-xs); font-size: var(--text-section); text-wrap: balance; }
  .stack-sm h2.h-sm { font-size: var(--text-md); }
  .links { display: flex; flex-wrap: wrap; gap: var(--space-xs) var(--space-sm); }
  .links a + a { padding-left: var(--space-sm); box-shadow: inset 1px 0 0 var(--border); }
  .bad-text { color: var(--bad); }
  /* Exposed: the panel's hairline and head take the error tone; no stripe. */
  .alert { border-color: color-mix(in oklab, var(--bad) 45%, var(--border)); }
  .alert h2 { color: var(--bad); }
  .reasons { display: flex; flex-direction: column; gap: var(--space-2xs); margin: 0; padding-left: var(--space-md); }
  .note { color: var(--warn); }
  .commands { display: flex; flex-direction: column; gap: var(--space-xs); }
  .kv { max-width: 96ch; }
  .state { display: flex; flex-wrap: wrap; align-items: center; gap: var(--space-xs); }
  .ips { display: flex; flex-wrap: wrap; gap: var(--space-2xs) var(--space-sm); }
  .dns { display: block; margin-top: var(--space-3xs); }
  .addr-head h2 { flex: none; }
  .addr-head .hint { text-align: right; }
</style>
