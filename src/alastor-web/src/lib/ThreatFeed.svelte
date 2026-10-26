<script lang="ts">
  import { onMount } from 'svelte';
  import { on } from './live.svelte';
  import { api, severities, type FeedPage, type FeedSource, type TagCount } from './api';
  import { number } from './format';
  import FeedRow from './FeedRow.svelte';
  import SourceHealth from './SourceHealth.svelte';
  import Icon from './ui/Icon.svelte';

  const PAGE_SIZE = 25;

  interface Filters {
    q: string;
    type: '' | 'cve' | 'news';
    minSeverity: string;
    exploited: boolean;
    tags: string[];
    sort: 'date' | 'date-asc' | 'severity';
    page: number;
  }

  // Filters live in the query string, so a filtered view can be bookmarked or shared.
  function readUrl(): Filters {
    const p = new URLSearchParams(location.search);
    const type = p.get('type');
    const sort = p.get('sort');
    return {
      q: p.get('q') ?? '',
      type: type === 'cve' || type === 'news' ? type : '',
      minSeverity: p.get('minSeverity') ?? '',
      exploited: p.get('exploited') === 'true',
      tags: p.getAll('tag'),
      sort: sort === 'severity' || sort === 'date-asc' ? sort : 'date',
      page: Math.max(1, Number(p.get('page')) || 1),
    };
  }

  function toParams(f: Filters, forApi: boolean): URLSearchParams {
    const p = new URLSearchParams();
    if (f.q.trim()) p.set('q', f.q.trim());
    if (f.type) p.set('type', f.type);
    if (f.minSeverity) p.set('minSeverity', f.minSeverity);
    if (f.exploited) p.set('exploited', 'true');
    for (const t of f.tags) p.append('tag', t);
    if (forApi) {
      p.set('sort', f.sort === 'severity' ? 'severity' : 'date');
      p.set('order', f.sort === 'date-asc' ? 'asc' : 'desc');
      p.set('page', String(f.page));
      p.set('pageSize', String(PAGE_SIZE));
    } else {
      if (f.sort !== 'date') p.set('sort', f.sort);
      if (f.page > 1) p.set('page', String(f.page));
    }
    return p;
  }

  const initial = readUrl();
  let filters = $state<Filters>(initial);
  let search = $state(initial.q); // the input; copied into filters.q after a short pause
  let data = $state<FeedPage | null>(null);
  let loading = $state(true);
  let error = $state('');
  let sources = $state<FeedSource[]>([]);
  let popularTags = $state<TagCount[]>([]);
  let pending = $state(0);
  let now = $state(Date.now());

  const active = $derived(!!(filters.q || filters.type || filters.minSeverity || filters.exploited || filters.tags.length));
  const pages = $derived(data ? Math.max(1, Math.ceil(data.total / PAGE_SIZE)) : 1);
  const shownTags = $derived([
    ...filters.tags,
    ...popularTags.map((t) => t.tag).filter((t) => !filters.tags.some((a) => a.toLowerCase() === t.toLowerCase())),
  ].slice(0, 16));

  let controller: AbortController | undefined;

  async function load() {
    controller?.abort();
    const mine = (controller = new AbortController());
    loading = true;
    try {
      const page = await api<FeedPage>(`/api/feed?${toParams(filters, true)}`, { signal: mine.signal });
      if (mine !== controller) return;
      data = page;
      error = '';
    } catch (e) {
      if (mine !== controller || (e instanceof DOMException && e.name === 'AbortError')) return;
      error = e instanceof Error ? e.message : 'Unknown error';
    } finally {
      if (mine === controller) loading = false;
    }
  }

  async function loadMeta() {
    // The list never waits on this: a failure only leaves the health strip and tag chips stale.
    const [s, t] = await Promise.allSettled([api<FeedSource[]>('/api/feed/sources'), api<TagCount[]>('/api/feed/tags?limit=16')]);
    if (s.status === 'fulfilled') sources = s.value;
    if (t.status === 'fulfilled') popularTags = t.value;
  }

  // Any filter change: sync the URL and reload.
  $effect(() => {
    const qs = toParams(filters, false).toString();
    history.replaceState(null, '', qs ? `/feed?${qs}` : '/feed');
    load();
  });

  $effect(() => {
    const value = search;
    const timer = setTimeout(() => {
      if (value !== filters.q) update({ q: value });
    }, 300);
    return () => clearTimeout(timer);
  });

  function update(change: Partial<Filters>) {
    filters = { ...filters, page: 1, ...change };
  }

  function toggleTag(tag: string) {
    const has = filters.tags.some((t) => t.toLowerCase() === tag.toLowerCase());
    update({ tags: has ? filters.tags.filter((t) => t.toLowerCase() !== tag.toLowerCase()) : [...filters.tags, tag] });
  }

  function clear() {
    search = '';
    filters = { q: '', type: '', minSeverity: '', exploited: false, tags: [], sort: filters.sort, page: 1 };
  }

  function goTo(page: number) {
    filters = { ...filters, page };
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }

  function showNew() {
    pending = 0;
    if (filters.page !== 1) filters = { ...filters, page: 1 };
    else load();
    loadMeta();
  }

  onMount(() => {
    loadMeta();
    const tick = setInterval(() => (now = Date.now()), 30_000);
    const meta = setInterval(loadMeta, 60_000);

    // Live hint from the server when the background fetch stores new items. Without it, the page still works
    // and the health strip refreshes every minute.
    const off = on('feedUpdated', (summary: { newItems: number }) => {
      pending += summary.newItems;
      loadMeta();
    });

    return () => {
      clearInterval(tick);
      clearInterval(meta);
      off();
    };
  });
</script>

<section class="feed">
  <div class="page-head">
    <div>
      <h1>Threat feed</h1>
      <p class="sub">New CVEs from NVD, CISA's Known Exploited Vulnerabilities and security news, in one timeline.</p>
    </div>
    <div class="actions"><SourceHealth {sources} {now} /></div>
  </div>

  <div class="filters" role="search">
    <div class="row">
      <label class="search">
        <span class="visually-hidden">Search</span>
        <Icon name="search" size={14} />
        <input class="field" type="search" placeholder="Search titles, products, CVE ids…" bind:value={search} />
      </label>

      <div class="seg" role="group" aria-label="Type">
        {#each [['', 'All'], ['cve', 'CVEs'], ['news', 'News']] as [value, label] (value)}
          <button class:on={filters.type === value} aria-pressed={filters.type === value} onclick={() => update({ type: value as Filters['type'] })}>{label}</button>
        {/each}
      </div>

      <label>
        <span class="visually-hidden">Minimum severity</span>
        <select class="field" value={filters.minSeverity} onchange={(e) => update({ minSeverity: e.currentTarget.value })}>
          <option value="">Any severity</option>
          {#each severities.slice(0, 4) as s (s)}
            <option value={s}>{s === 'Critical' ? 'Critical' : `${s} and above`}</option>
          {/each}
        </select>
      </label>

      <label class="toggle" class:on={filters.exploited}>
        <input type="checkbox" checked={filters.exploited} onchange={(e) => update({ exploited: e.currentTarget.checked })} />
        Actively exploited
      </label>

      <label class="sort">
        <span class="visually-hidden">Sort</span>
        <select class="field" value={filters.sort} onchange={(e) => update({ sort: e.currentTarget.value as Filters['sort'] })}>
          <option value="date">Newest first</option>
          <option value="date-asc">Oldest first</option>
          <option value="severity">Highest severity</option>
        </select>
      </label>
    </div>

    {#if shownTags.length}
      <div class="tags" aria-label="Filter by tag">
        {#each shownTags as tag (tag)}
          {@const on = filters.tags.some((t) => t.toLowerCase() === tag.toLowerCase())}
          <button class="tag" class:on aria-pressed={on} onclick={() => toggleTag(tag)}>{tag}{#if on}<Icon name="close" size={12} />{/if}</button>
        {/each}
        {#if active}
          <button class="btn ghost small" onclick={clear}>Clear filters</button>
        {/if}
      </div>
    {/if}
  </div>

  {#if pending > 0}
    <button class="new" onclick={showNew}><span class="nowrap">{number.format(pending)} new {pending === 1 ? 'item' : 'items'}</span><span class="show">Show</span></button>
  {/if}

  {#if error}
    <div class="banner bad error" role="alert">
      <Icon name="error" />
      <p>Couldn't load the feed: {error}</p>
      <button class="btn small" onclick={load}>Retry</button>
    </div>
  {/if}

  {#if data}
    <p class="count" aria-live="polite">
      {#if data.total === 0}
        No items
      {:else}
        {number.format((data.page - 1) * PAGE_SIZE + 1)} to {number.format(Math.min(data.page * PAGE_SIZE, data.total))} of {number.format(data.total)}
      {/if}
    </p>

    <ol class="list card" class:dim={loading}>
      {#each data.items as item (item.id)}
        <FeedRow {item} {now} activeTags={filters.tags} onTag={toggleTag} />
      {/each}
    </ol>

    {#if data.total === 0 && !loading}
      <div class="empty empty-dashed">
        {#if active}
          Nothing matches these filters. <button class="btn ghost small" onclick={clear}>Clear filters</button>
        {:else if sources.every((s) => !s.lastSuccessAt)}
          The first fetch is still running. Items appear here as sources respond.
        {:else}
          No items yet.
        {/if}
      </div>
    {/if}

    {#if pages > 1}
      <nav class="pager" aria-label="Pagination">
        <button class="btn" disabled={filters.page <= 1} onclick={() => goTo(filters.page - 1)}>Newer</button>
        <span class="figure-label">Page {filters.page} of {number.format(pages)}</span>
        <button class="btn" disabled={filters.page >= pages} onclick={() => goTo(filters.page + 1)}>Older</button>
      </nav>
    {/if}
  {:else if loading}
    <ol class="list card skeleton" aria-busy="true">
      {#each Array(6) as _, i (i)}<li></li>{/each}
    </ol>
  {/if}
</section>

<style>
  .feed { max-width: 1040px; }

  .filters {
    position: sticky;
    top: 0;
    z-index: var(--z-raised);
    display: flex;
    flex-direction: column;
    gap: var(--space-xs);
    padding: var(--space-sm) 0;
    margin-bottom: var(--space-xs);
    background: var(--bg);
    border-bottom: var(--rule-hair) solid var(--border);
  }
  .row { display: flex; flex-wrap: wrap; gap: var(--space-xs); align-items: center; }
  .search { position: relative; flex: 1 1 240px; display: flex; }
  .search :global(.icon) { position: absolute; left: var(--space-sm); top: 50%; translate: 0 -50%; color: var(--muted); pointer-events: none; }
  .search input { width: 100%; padding-left: var(--space-xl); }
  .seg { align-self: center; }

  .toggle {
    display: inline-flex;
    align-items: center;
    gap: var(--space-xs);
    min-height: var(--control);
    padding: 0 var(--space-sm);
    border: var(--rule-hair) solid var(--color-rule-2);
    border-radius: var(--radius-input);
    background: var(--color-key-face);
    color: var(--color-ink-2);
    font-family: var(--font-display);
    font-weight: 500;
    cursor: pointer;
    white-space: nowrap;
  }
  .toggle:hover { border-color: var(--color-ink-2); }
  .toggle.on { color: var(--exploited); border-color: color-mix(in oklab, var(--exploited) 45%, var(--border)); background: var(--exploited-bg); }
  .toggle input { accent-color: var(--exploited); }
  .toggle:has(input:focus-visible) { outline: 2px solid var(--focus); outline-offset: 2px; }

  .tags { display: flex; flex-wrap: wrap; gap: var(--space-2xs); align-items: center; }
  .tag {
    display: inline-flex;
    align-items: center;
    gap: var(--space-2xs);
    min-height: 24px;
    padding: 0 var(--space-xs);
    border: var(--rule-hair) solid transparent;
    border-radius: 4px;
    background: var(--color-paper-3);
    color: var(--color-ink-2);
    font-size: var(--text-xs);
    font-weight: 500;
    cursor: pointer;
    transition: background-color var(--dur-micro) var(--ease-out), color var(--dur-micro) var(--ease-out);
  }
  .tag:hover { color: var(--text-strong); background: var(--color-rule); }
  .tag:active { background: var(--color-rule-2); }
  .tag.on { background: var(--color-accent-wash); border-color: color-mix(in oklab, var(--color-accent) 35%, var(--border)); color: var(--color-accent-deep); }

  .new {
    display: flex;
    justify-content: center;
    align-items: center;
    gap: var(--space-sm);
    width: 100%;
    margin: var(--space-xs) 0;
    min-height: var(--control);
    padding: var(--space-xs) var(--space-md);
    border: var(--rule-hair) solid color-mix(in oklab, var(--color-accent) 40%, var(--border));
    border-radius: var(--radius-input);
    background: var(--color-accent-wash);
    color: var(--color-accent-deep);
    font-family: var(--font-display);
    font-weight: 500;
    cursor: pointer;
  }
  .new:hover { border-color: var(--color-accent); }
  .new:active { background: var(--color-paper-3); }
  .new .show { padding-left: var(--space-sm); border-left: var(--rule-hair) solid color-mix(in oklab, var(--color-accent) 40%, var(--border)); text-decoration: underline; text-underline-offset: 0.16em; }
  .error { align-items: center; margin: var(--space-xs) 0; }
  .error p { flex: 1; }
  .error :global(.icon) { color: var(--bad); }
  .count { margin: var(--space-sm) 0 var(--space-xs); color: var(--muted); font-family: var(--font-display); font-weight: 500; font-size: var(--text-sm); font-variant-numeric: tabular-nums; }

  .list { list-style: none; margin: 0; padding: 0; overflow: hidden; transition: opacity var(--dur-short) var(--ease-out); }
  .list:empty { display: none; }
  .list.dim { opacity: 0.55; }
  .skeleton li { height: 104px; border-bottom: var(--rule-hair) solid var(--border); background: linear-gradient(90deg, var(--color-paper-2) 0%, var(--color-paper-3) 50%, var(--color-paper-2) 100%); background-size: 200% 100%; animation: shimmer 1.4s linear infinite; }
  .skeleton li:last-child { border-bottom: 0; }
  @keyframes shimmer { to { background-position: -200% 0; } }
  @media (prefers-reduced-motion: reduce) { .skeleton li { animation: none; } }

  .empty .btn { vertical-align: baseline; }

  .pager { display: flex; justify-content: center; align-items: center; gap: var(--space-md); margin: var(--space-lg) 0; font-variant-numeric: tabular-nums; }

  @media (max-width: 60rem) {
    /* Under 60rem the shell has its own sticky bar, and the wrapped filters would cover half the screen. */
    .filters { position: static; }
  }
  @media (max-width: 640px) {
    .row > label:not(.search), .seg { flex: 1 1 auto; }
    .row select { width: 100%; }
    .seg button { flex: 1; }
  }
</style>
