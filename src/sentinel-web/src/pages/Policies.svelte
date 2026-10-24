<script lang="ts">
  import { api, errorText, type PolicyLayer } from '../lib/api';
  import { fleet } from '../lib/fleet.svelte';
  import { refreshOn } from '../lib/live.svelte';
  import { navigate } from '../lib/router.svelte';
  import { canWrite } from '../lib/session.svelte';
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

{#if error}<div class="banner bad" role="alert"><p>{error}</p></div>{/if}

<div class="stack">
  <section class="card">
    <header><h2>Global</h2><span class="hint">applies to every host</span></header>
    <a class="layer" href="/policies/global">
      <div>
        <strong>All hosts</strong>
        <div class="muted small">Banning defaults, schedules and agent timings for the whole fleet.</div>
      </div>
      <div class="meta">
        {#if global}<span class="pill muted">v{global.currentVersion}</span> <span class="muted small">{global.updatedBy} · <Time iso={global.updatedAt} /></span>{/if}
        <span class="go">{canWrite() ? 'Edit' : 'View'} →</span>
      </div>
    </a>
  </section>

  <section class="card">
    <header><h2>Groups</h2><a class="hint" href="/settings/groups">Manage groups →</a></header>
    {#if fleet.groups.length}
      {#each fleet.groups as g (g.id)}
        {@const l = layerFor('Group', g.id)}
        <a class="layer" href="/policies/group/{g.id}">
          <div>
            <strong>{g.name}</strong>
            <div class="muted small">{g.hostCount} host{g.hostCount === 1 ? '' : 's'}{g.description ? ` · ${g.description}` : ''}</div>
          </div>
          <div class="meta">
            {#if l}<span class="pill info">v{l.currentVersion}</span> <span class="muted small">{l.updatedBy} · <Time iso={l.updatedAt} /></span>
            {:else}<span class="muted small">no overrides</span>{/if}
            <span class="go">{canWrite() ? (l ? 'Edit' : 'Add overrides') : 'View'} →</span>
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
        <div><strong>{l.targetName}</strong></div>
        <div class="meta">
          <span class="pill info">v{l.currentVersion}</span> <span class="muted small">{l.updatedBy} · <Time iso={l.updatedAt} /></span>
          <span class="go">{canWrite() ? 'Edit' : 'View'} →</span>
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
  .layer { display: flex; justify-content: space-between; align-items: center; gap: 12px; padding: 12px 16px; border-bottom: 1px solid var(--border); color: inherit; flex-wrap: wrap; }
  .layer:last-child { border-bottom: 0; }
  .layer:hover { background: var(--surface-2); text-decoration: none; }
  .meta { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
  .go { color: var(--link); font-size: 13px; }
  .add { display: flex; gap: 8px; padding: 12px 16px; border-top: 1px solid var(--border); flex-wrap: wrap; }
</style>
