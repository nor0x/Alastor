<script lang="ts">
  import { api, errorText, type PolicyLayer } from '../lib/api';
  import { fleet } from '../lib/fleet.svelte';
  import { refreshOn } from '../lib/live.svelte';
  import { navigate } from '../lib/router.svelte';
  import { canWrite } from '../lib/session.svelte';
  import Icon from '../lib/ui/Icon.svelte';
  import Time from '../lib/ui/Time.svelte';

  let layers = $state<PolicyLayer[]>([]);
  let error = $state('');
  let addHost = $state('');

  async function load() {
    try {
      layers = await api<PolicyLayer[]>('/api/policies');
      error = '';
    } catch (e) {
      error = errorText(e);
    }
  }
  $effect(() => {
    load();
    return refreshOn(['policyChanged'], load);
  });

  const global = $derived(layers.find((l) => l.scope === 'Global'));
  const layerFor = (scope: 'Group' | 'Host', id: string) => layers.find((l) => l.scope === scope && l.targetId === id);
  const hostLayers = $derived(layers.filter((l) => l.scope === 'Host'));
  const hostsWithout = $derived(fleet.hosts.filter((h) => !layerFor('Host', h.id)));
</script>

<div class="page-head">
  <div>
    <h1>Policies</h1>
    <p class="sub">Declarative YAML in three layers. Each host gets <strong>global → its group → its own overrides</strong>, merged key by key.</p>
  </div>
</div>

{#if error}<div class="banner bad spaced" role="alert"><Icon name="error" /><p>{error}</p></div>{/if}

<div class="stack">
  <section class="card">
    <header><h2>Global</h2><span class="hint">applies to every host</span></header>
    <a class="layer" href="/policies/global">
      <div class="what">
        <strong>All hosts</strong>
        <span class="muted small">Banning defaults, schedules and agent timings for the whole fleet.</span>
      </div>
      <div class="meta">
        {#if global}<span class="ver mono">v{global.currentVersion}</span><span class="by muted small">{global.updatedBy}</span><span class="when muted small"><Time iso={global.updatedAt} /></span>{/if}
        <span class="go">{canWrite() ? 'Edit' : 'View'}</span>
      </div>
    </a>
  </section>

  <section class="card">
    <header><h2>Groups</h2><a class="hint" href="/settings/groups">Manage groups</a></header>
    {#if fleet.groups.length}
      {#each fleet.groups as g (g.id)}
        {@const l = layerFor('Group', g.id)}
        <a class="layer" href="/policies/group/{g.id}">
          <div class="what">
            <strong>{g.name}</strong>
            <span class="facts muted small"><span>{g.hostCount} host{g.hostCount === 1 ? '' : 's'}</span>{#if g.description}<span>{g.description}</span>{/if}</span>
          </div>
          <div class="meta">
            {#if l}<span class="ver mono">v{l.currentVersion}</span><span class="by muted small">{l.updatedBy}</span><span class="when muted small"><Time iso={l.updatedAt} /></span>
            {:else}<span class="muted small">no overrides</span>{/if}
            <span class="go">{canWrite() ? (l ? 'Edit' : 'Add overrides') : 'View'}</span>
          </div>
        </a>
      {/each}
    {:else}
      <div class="empty">No groups yet. Groups let you give a set of hosts (say, all web servers) their own banning rules. <a href="/settings/groups">Create a group</a></div>
    {/if}
  </section>

  <section class="card">
    <header><h2>Host overrides</h2><span class="hint">for one-off exceptions</span></header>
    {#each hostLayers as l (l.id)}
      <a class="layer" href="/policies/host/{l.targetId}">
        <div class="what"><strong>{l.targetName}</strong></div>
        <div class="meta">
          <span class="ver mono">v{l.currentVersion}</span><span class="by muted small">{l.updatedBy}</span><span class="when muted small"><Time iso={l.updatedAt} /></span>
          <span class="go">{canWrite() ? 'Edit' : 'View'}</span>
        </div>
      </a>
    {:else}
      <div class="empty">No host has its own overrides.</div>
    {/each}
    {#if canWrite() && hostsWithout.length}
      <form class="add" onsubmit={(e) => { e.preventDefault(); if (addHost) navigate(`/policies/host/${addHost}`); }}>
        <select class="field" bind:value={addHost} aria-label="Host">
          <option value="">Choose a host…</option>
          {#each hostsWithout as h (h.id)}<option value={h.id}>{h.name}</option>{/each}
        </select>
        <button class="btn" disabled={!addHost}>Add host overrides</button>
      </form>
    {/if}
  </section>
</div>

<style>
  .spaced { margin-bottom: var(--space-md); }
  .banner > :global(.icon) { margin-top: var(--space-3xs); color: var(--bad); }
  .layer {
    display: flex; justify-content: space-between; align-items: center; gap: var(--space-xs) var(--space-md); flex-wrap: wrap;
    min-height: 56px; padding: var(--space-sm) var(--space-md); border-bottom: var(--rule-hair) solid var(--border); color: inherit;
    transition: background-color var(--dur-micro) var(--ease-out);
  }
  .layer:last-child { border-bottom: 0; }
  .layer:hover { background: var(--color-paper-2); text-decoration: none; }
  .layer:active { background: var(--color-paper-3); }
  .layer:focus-visible { outline-offset: -2px; }
  .what { display: flex; flex-direction: column; gap: var(--space-3xs); min-width: 0; flex: 1 1 260px; }
  .what strong { font-family: var(--font-display); font-weight: 600; font-size: var(--text-lg); color: var(--text-strong); }
  .facts { display: flex; flex-wrap: wrap; gap: var(--space-xs); }
  .facts > span + span { padding-left: var(--space-xs); border-left: var(--rule-hair) solid var(--border-strong); }
  .meta { display: flex; align-items: center; gap: var(--space-xs) var(--space-sm); flex-wrap: wrap; }
  .ver { padding: 0 var(--space-2xs); border-radius: 4px; background: var(--color-paper-3); color: var(--color-ink); line-height: 20px; }
  .when { padding-left: var(--space-sm); border-left: var(--rule-hair) solid var(--border-strong); }
  .go { min-width: 96px; text-align: right; font-family: var(--font-display); font-weight: 500; font-size: var(--text-sm); color: var(--link); }
  .layer:hover .go { text-decoration: underline; text-decoration-color: var(--color-accent); }
  .add { display: flex; gap: var(--space-xs); flex-wrap: wrap; padding: var(--space-sm) var(--space-md); border-top: var(--rule-hair) solid var(--border); background: var(--color-paper-2); }
  .add select { flex: 0 1 280px; }
</style>
