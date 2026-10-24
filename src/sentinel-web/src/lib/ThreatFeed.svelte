<script lang="ts">
  import { onMount } from 'svelte';
  import { HubConnectionBuilder, LogLevel } from '@microsoft/signalr';
  import { api, severities, type FeedPage, type FeedSource, type TagCount } from './api';
  import { number } from './format';
  import FeedRow from './FeedRow.svelte';
  import SourceHealth from './SourceHealth.svelte';

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
    history.replaceState(null, '', qs ? `?${qs}` : location.pathname);
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
    const hub = new HubConnectionBuilder().withUrl('/hubs/dashboard').withAutomaticReconnect().configureLogging(LogLevel.Warning).build();
    hub.on('feedUpdated', (summary: { newItems: number }) => {
      pending += summary.newItems;
      loadMeta();
    });
    hub.start().catch(() => {});

    return () => {
      clearInterval(tick);
      clearInterval(meta);
      hub.stop();
    };
  });
</script>

<section class="feed">
  <div class="head">
    <div>
      <h1>Threat feed</h1>
      <p class="sub">New CVEs from NVD, CISA's Known Exploited Vulnerabilities and security news, in one timeline.</p>
    </div>
    <SourceHealth {sources} {now} />
  </div>

  <div class="filters" role="search">
    <div class="row">
      <label class="search">
        <span class="visually-hidden">Search</span>
        <svg viewBox="0 0 16 16" width="14" height="14" aria-hidden="true"><path fill="currentColor" d="M10.68 11.74a6 6 0 1 1 1.06-1.06l3.04 3.04a.75.75 0 1 1-1.06 1.06ZM11.5 7a4.5 4.5 0 1 0-9 0 4.5 4.5 0 0 0 9 0Z" /></svg>
        <input class="field" type="search" placeholder="Search titles, products, CVE ids…" bind:value={search} />
      </label>

      <div class="segmented" role="group" aria-label="Type">
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
          <button class="tag" class:on aria-pressed={on} onclick={() => toggleTag(tag)}>{tag}{#if on}<span aria-hidden="true"> ×</span>{/if}</button>
        {/each}
        {#if active}
          <button class="clear" onclick={clear}>Clear filters</button>
        {/if}
      </div>
    {/if}
  </div>

  {#if pending > 0}
    <button class="new" onclick={showNew}>{number.format(pending)} new {pending === 1 ? 'item' : 'items'} · Show</button>
  {/if}

  {#if error}
    <div class="error" role="alert">
      Couldn't load the feed: {error}
      <button class="btn" onclick={load}>Retry</button>
    </div>
  {/if}

  {#if data}
    <p class="count" aria-live="polite">
      {#if data.total === 0}
        No items
      {:else}
        {number.format((data.page - 1) * PAGE_SIZE + 1)}–{number.format(Math.min(data.page * PAGE_SIZE, data.total))} of {number.format(data.total)}
      {/if}
    </p>

    <ol class="list" class:dim={loading}>
      {#each data.items as item (item.id)}
        <FeedRow {item} {now} activeTags={filters.tags} onTag={toggleTag} />
      {/each}
    </ol>

    {#if data.total === 0 && !loading}
      <div class="empty">
        {#if active}
          Nothing matches these filters. <button class="link" onclick={clear}>Clear filters</button>
        {:else if sources.every((s) => !s.lastSuccessAt)}
          The first fetch is still running. Items appear here as sources respond.
        {:else}
          No items yet.
        {/if}
      </div>
    {/if}

    {#if pages > 1}
      <nav class="pager" aria-label="Pagination">
        <button class="btn" disabled={filters.page <= 1} onclick={() => goTo(filters.page - 1)}>← Newer</button>
        <span>Page {filters.page} of {number.format(pages)}</span>
        <button class="btn" disabled={filters.page >= pages} onclick={() => goTo(filters.page + 1)}>Older →</button>
      </nav>
    {/if}
  {:else if loading}
    <ol class="list skeleton" aria-busy="true">
      {#each Array(6) as _, i (i)}<li></li>{/each}
    </ol>
  {/if}
</section>

<style>
  .head { display: flex; justify-content: space-between; align-items: flex-start; gap: 16px; flex-wrap: wrap; margin-bottom: 16px; }
  h1 { margin: 0; font-size: 22px; color: var(--text-strong); }
  .sub { margin: 4px 0 0; color: var(--muted); }

  .filters {
    position: sticky;
    top: 49px;
    z-index: 5;
    display: flex;
    flex-direction: column;
    gap: 10px;
    padding: 12px;
    margin: 0 -12px 8px;
    background: var(--bg);
    border-bottom: 1px solid var(--border);
  }
  .row { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
  .search { position: relative; flex: 1 1 240px; display: flex; }
  .search svg { position: absolute; left: 10px; top: 50%; transform: translateY(-50%); color: var(--muted); }
  .search input { width: 100%; padding-left: 30px; }

  .segmented { display: inline-flex; border: 1px solid var(--border-strong); border-radius: var(--radius); overflow: hidden; }
  .segmented button { padding: 5px 12px; border: 0; background: var(--bg); cursor: pointer; color: var(--muted); }
  .segmented button + button { border-left: 1px solid var(--border-strong); }
  .segmented button.on { background: var(--surface-2); color: var(--text-strong); }

  .toggle {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 5px 10px;
    border: 1px solid var(--border-strong);
    border-radius: var(--radius);
    cursor: pointer;
    color: var(--muted);
    white-space: nowrap;
  }
  .toggle.on { color: var(--exploited); border-color: var(--exploited); background: var(--exploited-bg); }
  .toggle input { accent-color: var(--sev-critical); margin: 0; }

  .tags { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; }
  .tag {
    padding: 1px 9px;
    border: 1px solid var(--border-strong);
    border-radius: 999px;
    background: transparent;
    color: var(--muted);
    font-size: 12px;
    cursor: pointer;
  }
  .tag:hover { color: var(--text-strong); }
  .tag.on { background: rgba(56, 139, 253, 0.15); border-color: var(--link); color: var(--link); }
  .clear, .link { border: 0; background: none; color: var(--link); cursor: pointer; font-size: 12px; padding: 0 4px; }
  .link { font-size: inherit; }

  .new {
    display: block;
    width: 100%;
    margin: 8px 0;
    padding: 8px;
    border: 1px solid var(--focus);
    border-radius: var(--radius);
    background: rgba(31, 111, 235, 0.12);
    color: var(--link);
    cursor: pointer;
    font-weight: 500;
  }
  .error {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 12px;
    margin: 8px 0;
    padding: 10px 12px;
    border: 1px solid var(--sev-critical);
    border-radius: var(--radius);
    background: var(--exploited-bg);
  }
  .count { margin: 8px 0; color: var(--muted); font-size: 12px; }

  .list { list-style: none; margin: 0; padding: 0; border: 1px solid var(--border); border-radius: var(--radius); overflow: hidden; transition: opacity 0.15s; }
  .list:empty { display: none; }
  .list.dim { opacity: 0.55; }
  .skeleton li { height: 104px; border-bottom: 1px solid var(--border); background: linear-gradient(90deg, var(--surface) 0%, var(--surface-2) 50%, var(--surface) 100%); background-size: 200% 100%; animation: shimmer 1.4s infinite; }
  @keyframes shimmer { to { background-position: -200% 0; } }
  @media (prefers-reduced-motion: reduce) { .skeleton li { animation: none; } }

  .empty { padding: 48px 16px; text-align: center; color: var(--muted); border: 1px dashed var(--border-strong); border-radius: var(--radius); }

  .pager { display: flex; justify-content: center; align-items: center; gap: 16px; margin: 20px 0; color: var(--muted); }

  @media (max-width: 640px) {
    /* On a phone the wrapped filter bar would cover half the screen if it stayed pinned. */
    .filters { position: static; margin: 0 -16px 8px; padding: 10px 16px; }
    .row > label:not(.search), .segmented { flex: 1 1 auto; }
    .row select { width: 100%; }
    .segmented button { flex: 1; }
  }
</style>
