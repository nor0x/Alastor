<script lang="ts">
  import { untrack } from 'svelte';
  import { api, capabilities, errorText, severities, type EventPage, type SecurityEvent } from '../lib/api';
  import { fleet, hostNames } from '../lib/fleet.svelte';
  import { live, on } from '../lib/live.svelte';
  import { route } from '../lib/router.svelte';
  import { number } from '../lib/format';
  import EventList from '../lib/ui/EventList.svelte';
  import Icon from '../lib/ui/Icon.svelte';

  interface Filters { hostId: string; minSeverity: string; capability: string; ip: string; q: string; range: string }
  const keys: (keyof Filters)[] = ['hostId', 'minSeverity', 'capability', 'ip', 'q', 'range'];

  function read(): Filters {
    const p = new URLSearchParams(route.search);
    return { hostId: p.get('hostId') ?? '', minSeverity: p.get('minSeverity') ?? '', capability: p.get('capability') ?? '', ip: p.get('ip') ?? '', q: p.get('q') ?? '', range: p.get('range') ?? '' };
  }

  const initial = read();
  let filters = $state<Filters>(initial);
  let search = $state(initial.q);
  let ipInput = $state(initial.ip);
  let items = $state<SecurityEvent[]>([]);
  let next = $state<string | null>(null);
  let loading = $state(true);
  let error = $state('');
  let pending = $state(0);

  const active = $derived(keys.some((k) => filters[k]));

  // Links elsewhere in the app (an IP in a ban row, "all alerts") change the query string: follow them.
  $effect(() => {
    void route.search;
    const f = read();
    if (untrack(() => keys.some((k) => f[k] !== filters[k]))) {
      filters = f;
      search = f.q;
      ipInput = f.ip;
    }
  });

  function params(before?: string | null): URLSearchParams {
    const p = new URLSearchParams({ limit: '100' });
    if (filters.hostId) p.set('hostId', filters.hostId);
    if (filters.minSeverity) p.set('minSeverity', filters.minSeverity);
    if (filters.capability) p.set('capability', filters.capability);
    if (filters.ip) p.set('ip', filters.ip);
    if (filters.q) p.set('q', filters.q);
    if (filters.range) p.set('from', new Date(Date.now() - Number(filters.range) * 3600_000).toISOString());
    if (before) p.set('before', before);
    return p;
  }

  async function load(more = false) {
    loading = true;
    try {
      const page = await api<EventPage>(`/api/events?${params(more ? next : null)}`);
      items = more ? [...items, ...page.items] : page.items;
      next = page.nextBefore;
      error = '';
      if (!more) pending = 0;
    } catch (e) {
      error = errorText(e);
    } finally {
      loading = false;
    }
  }

  $effect(() => {
    const qs = new URLSearchParams(Object.entries(filters).filter(([, v]) => v)).toString();
    history.replaceState(null, '', qs ? `/events?${qs}` : '/events');
    route.search = qs ? `?${qs}` : '';
    load();
  });

  $effect(() => {
    const v = search.trim();
    const t = setTimeout(() => v !== filters.q && (filters = { ...filters, q: v }), 300);
    return () => clearTimeout(t);
  });

  // New events don't reshuffle the list under the reader: count them and offer a reload.
  $effect(() => {
    const off = on('eventsCreated', (list: SecurityEvent[]) => (pending += list.length));
    const poll = setInterval(() => !live.connected && load(), 30_000);
    return () => { off(); clearInterval(poll); };
  });

  function set(change: Partial<Filters>) {
    filters = { ...filters, ...change };
  }
  function clear() {
    search = '';
    ipInput = '';
    filters = { hostId: '', minSeverity: '', capability: '', ip: '', q: '', range: '' };
  }
</script>

<div class="page-head">
  <div>
    <h1>Events</h1>
    <p class="sub">Everything the agents and the server reported, normalized into one timeline.</p>
  </div>
</div>

<div class="filterbar" role="search">
  <input class="field grow" type="search" placeholder="Search messages…" bind:value={search} aria-label="Search messages" />
  <form class="ip" onsubmit={(e) => { e.preventDefault(); set({ ip: ipInput.trim() }); }}>
    <input class="field mono" placeholder="IP address" bind:value={ipInput} onblur={() => set({ ip: ipInput.trim() })} aria-label="IP address" />
  </form>
  <select class="field" value={filters.hostId} onchange={(e) => set({ hostId: e.currentTarget.value })} aria-label="Host">
    <option value="">All hosts</option>
    {#each fleet.hosts as h (h.id)}<option value={h.id}>{h.name}</option>{/each}
  </select>
  <select class="field" value={filters.minSeverity} onchange={(e) => set({ minSeverity: e.currentTarget.value })} aria-label="Minimum severity">
    <option value="">Any severity</option>
    {#each severities.slice(0, 4) as s (s)}<option value={s}>{s === 'Critical' ? 'Critical' : `${s} and above`}</option>{/each}
  </select>
  <select class="field" value={filters.capability} onchange={(e) => set({ capability: e.currentTarget.value })} aria-label="Capability">
    <option value="">All capabilities</option>
    {#each capabilities as c (c)}<option value={c}>{c}</option>{/each}
  </select>
  <select class="field" value={filters.range} onchange={(e) => set({ range: e.currentTarget.value })} aria-label="Time range">
    <option value="">All time</option>
    <option value="1">Last hour</option>
    <option value="24">Last 24 hours</option>
    <option value="168">Last 7 days</option>
  </select>
  {#if active}<button class="btn ghost" onclick={clear}>Clear</button>{/if}
</div>

{#if pending > 0}
  <button class="new" onclick={() => load()}><Icon name="info" /><span class="new-n">{number.format(pending)} new event{pending === 1 ? '' : 's'}</span><span class="new-go">Show</span></button>
{/if}
{#if error}<div class="banner bad" role="alert"><p>Couldn't load events: {error}</p><button class="btn small" onclick={() => load()}>Retry</button></div>{/if}

<section class="card" class:dim={loading && items.length > 0}>
  {#if items.length}
    <EventList events={items} hostNames={hostNames()} />
    {#if next}<div class="more"><button class="btn" disabled={loading} onclick={() => load(true)}>Load older</button></div>{/if}
  {:else if loading}
    <div class="skeleton-block"></div>
  {:else}
    <div class="empty">{active ? 'No events match these filters.' : 'No events yet. They appear as agents report.'}</div>
  {/if}
</section>

<style>
  .ip { display: contents; }
  .ip input { width: 150px; }
  .new {
    display: flex; align-items: center; gap: var(--space-xs); width: 100%; min-height: 40px; margin: 0 0 var(--space-xs); padding: 0 var(--space-md);
    border: var(--rule-hair) solid color-mix(in oklab, var(--color-accent) 40%, var(--border)); border-radius: var(--radius-input);
    background: var(--color-accent-wash); color: var(--color-accent-deep); cursor: pointer;
    font-family: var(--font-display); font-weight: 500; font-size: var(--text-md); text-align: left;
    transition: background-color var(--dur-micro) var(--ease-out);
  }
  .new:hover { background: color-mix(in oklab, var(--color-accent-wash) 70%, var(--color-accent) 12%); }
  .new-n { flex: 1; color: var(--text-strong); font-variant-numeric: tabular-nums; }
  .new-go { text-decoration: underline; text-decoration-color: var(--color-accent); }
  .dim { opacity: 0.6; transition: opacity var(--dur-short) var(--ease-out); }
  .banner { margin-bottom: var(--space-xs); justify-content: space-between; align-items: center; }
  @media (max-width: 640px) {
    .ip input { width: auto; flex: 1 1 140px; }
    .filterbar select { flex: 1 1 140px; }
  }
</style>
