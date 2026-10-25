<script lang="ts">
  import { api, errorText, type FleetNetworkRow } from './api';
  import { refreshOn } from './live.svelte';
  import { exposureLook, firewallLabels, isExposed } from './network';
  import Time from './ui/Time.svelte';

  let rows = $state<FleetNetworkRow[] | null>(null);
  let error = $state('');

  async function load() {
    try {
      rows = await api<FleetNetworkRow[]>('/api/network');
      error = '';
    } catch (e) {
      error = errorText(e);
    }
  }

  $effect(() => {
    load();
    return refreshOn(['hostUpdated', 'policyChanged'], load, 60_000);
  });

  const rank = (r: FleetNetworkRow) => (isExposed(r.exposure, r.accepted) ? (r.passwordAuth ? 0 : 1) : r.exposure === null ? 3 : 2);
  const sorted = $derived((rows ?? []).slice().sort((a, b) => rank(a) - rank(b) || a.name.localeCompare(b.name)));
  const exposed = $derived(rows?.filter((r) => isExposed(r.exposure, r.accepted)) ?? []);
  const onTailnet = $derived(rows?.filter((r) => r.tailscaleState === 'Running') ?? []);
  const checked = $derived(rows?.filter((r) => r.checkedAt) ?? []);
</script>

{#if error && !rows}
  <div class="banner bad" role="alert"><p>Couldn't load network checks: {error}</p></div>
{:else if !rows}
  <div class="skeleton-block"></div>
{:else}
  <section class="summary card" aria-label="SSH exposure summary">
    <div class="stat">
      <span class="label">SSH open to the internet</span>
      <span class="big" class:bad={exposed.length > 0}>{checked.length ? exposed.length : '—'}<span class="of">/ {rows.length}</span></span>
    </div>
    <div class="stat">
      <span class="label">On a tailnet</span>
      <span class="big">{onTailnet.length}<span class="of">/ {rows.length}</span></span>
    </div>
    <p class="muted small explain">
      Each agent works out whether sshd can be reached from the internet: its ports and listening sockets, the host's addresses, and the
      ufw or nftables rules. Provider firewalls and security groups aren't visible to it. Open a host's <strong>Network</strong> tab for the
      reasons and the commands that close the port.
    </p>
  </section>

  <section class="card">
    <div class="table-wrap">
      <table class="table">
        <thead><tr><th>Host</th><th>SSH</th><th>Other public</th><th class="hide-sm">Passwords</th><th class="hide-sm">Host firewall</th><th>Tailscale</th><th class="hide-sm">Checked</th></tr></thead>
        <tbody>
          {#each sorted as r (r.hostId)}
            {@const look = exposureLook(r.exposure, r.accepted)}
            <tr>
              <td>
                <a href="/hosts/{r.hostId}?tab=network" class="name">{r.name}</a>
                {#if r.groupName}<span class="pill info">{r.groupName}</span>{/if}
                {#if r.error}<div class="small bad-text" title={r.error}>last check failed</div>{/if}
              </td>
              <td class="nowrap"><span class="pill {look.tone}">{look.label}</span>{#if r.ports.length && r.ports[0] !== 22} <span class="muted small">:{r.ports.join(',')}</span>{/if}</td>
              <td class="small">
                {#if r.publicServices === null}<span class="muted">—</span>
                {:else if r.publicServices.length}<a href="/hosts/{r.hostId}?tab=network"><span class="pill bad" title={r.publicServices.join(', ')}>{r.publicServices.length} unexpected</span></a>
                {:else}<span class="muted">{r.publicTotal ? `${r.publicTotal} allowed` : 'none'}</span>{/if}
              </td>
              <td class="hide-sm">{#if r.passwordAuth === null}<span class="muted">—</span>{:else if r.passwordAuth}<span class="bad-text">allowed</span>{:else}<span class="muted">off</span>{/if}</td>
              <td class="hide-sm small">{#if r.firewall}{r.firewallTool ?? ''} <span class="muted">{firewallLabels[r.firewall]}</span>{:else}<span class="muted">—</span>{/if}</td>
              <td class="nowrap small">
                {#if r.tailscaleState === 'Running'}<span class="pill ok">✓ {r.tailscaleIp}</span>{#if r.tailscaleSsh} <span class="muted">SSH</span>{/if}
                {:else if r.tailscaleState}<span class="pill warn">{r.tailscaleState === 'NeedsLogin' ? 'needs login' : r.tailscaleState === 'NotRunning' ? 'not running' : r.tailscaleState}</span>
                {:else}<span class="muted">—</span>{/if}
              </td>
              <td class="hide-sm nowrap">{#if r.checkedAt}<Time iso={r.checkedAt} />{:else}<span class="muted">never</span>{/if}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  </section>
{/if}

<style>
  .summary { display: flex; flex-wrap: wrap; align-items: center; gap: 16px 40px; padding: 16px; margin-bottom: 16px; }
  .stat { display: flex; flex-direction: column; gap: 4px; }
  .label { font-size: 12px; color: var(--muted); }
  .big { font-size: 30px; font-weight: 600; line-height: 1; font-variant-numeric: tabular-nums; color: var(--text-strong); }
  .big.bad { color: var(--bad); }
  .of { font-size: 14px; font-weight: 400; color: var(--muted); margin-left: 4px; }
  .explain { flex: 1; min-width: 240px; margin: 0; }
  .name { font-weight: 600; margin-right: 6px; }
  .bad-text { color: var(--bad); }
</style>
