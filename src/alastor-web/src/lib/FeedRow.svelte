<script lang="ts">
  import type { FeedItem } from './api';
  import { fullDate, timeAgo } from './format';

  let { item, now, activeTags, onTag }: { item: FeedItem; now: number; activeTags: string[]; onTag: (tag: string) => void } = $props();

  // Tags that only repeat what the row already shows (the KEV badge, CVE ids already in the title) are left out.
  const tags = $derived(item.tags.filter((t) => t !== 'kev' && !(item.type === 'cve' && t.toUpperCase() === item.id)).slice(0, 6));
</script>

<li class="row" class:exploited={item.exploited}>
  <div class="meta">
    <span class="source" class:cve={item.type === 'cve'} title={item.type === 'cve' ? 'Vulnerability' : 'News'}>{item.sourceName}</span>
    <time datetime={item.publishedAt} title={fullDate(item.publishedAt)}>{timeAgo(item.publishedAt, now)}</time>
    {#if item.severity}
      <span class="sev sev-{item.severity.toLowerCase()}" title="CVSS base severity">
        {item.severity}{#if item.cvssScore !== null}<span class="score">{item.cvssScore.toFixed(1)}</span>{/if}
      </span>
    {:else if item.type === 'cve'}
      <span class="sev unscored" title="NVD has not scored this CVE yet">Unscored</span>
    {/if}
    {#if item.exploited}
      <span class="kev" title={item.type === 'cve' ? 'Listed in the CISA Known Exploited Vulnerabilities catalog' : 'Mentions a CVE listed in the CISA KEV catalog'}>
        <svg viewBox="0 0 16 16" width="12" height="12" aria-hidden="true"><path fill="currentColor" d="M6.46 1.34a1.75 1.75 0 0 1 3.08 0l6.09 11.17A1.75 1.75 0 0 1 14.09 15H1.91a1.75 1.75 0 0 1-1.54-2.49ZM8 5a.75.75 0 0 0-.75.75v3.5a.75.75 0 0 0 1.5 0v-3.5A.75.75 0 0 0 8 5Zm0 7.5a1 1 0 1 0 0-2 1 1 0 0 0 0 2Z" /></svg>
        Actively exploited
      </span>
    {/if}
  </div>

  <h2><a href={item.url} target="_blank" rel="noopener noreferrer">{item.title}</a></h2>

  {#if item.summary}<p class="summary">{item.summary}</p>{/if}

  {#if tags.length || item.products.length}
    <div class="foot">
      {#if item.products.length}<span class="products">{item.products.slice(0, 3).join(' · ')}</span>{/if}
      {#each tags as tag (tag)}
        <button class="tag" class:on={activeTags.some((t) => t.toLowerCase() === tag.toLowerCase())} onclick={() => onTag(tag)}>#{tag}</button>
      {/each}
    </div>
  {/if}
</li>

<style>
  .row {
    padding: 14px 16px;
    border-bottom: 1px solid var(--border);
    background: var(--surface);
    border-left: 3px solid transparent;
  }
  .row:last-child { border-bottom: 0; }
  .row:hover { background: var(--surface-2); }
  .row.exploited { border-left-color: var(--sev-critical); }

  .meta { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; font-size: 12px; color: var(--muted); }
  .source {
    padding: 0 7px;
    border: 1px solid var(--border-strong);
    border-radius: 4px;
    color: var(--text);
    font-weight: 500;
    line-height: 18px;
  }
  .source.cve { border-color: rgba(88, 166, 255, 0.4); color: var(--link); }

  .unscored { --c: var(--sev-info); font-weight: 500; text-transform: none; font-size: 12px; }

  .kev {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    padding: 0 8px;
    border-radius: 999px;
    background: var(--sev-critical);
    color: #fff;
    font-weight: 600;
    font-size: 11px;
    line-height: 18px;
  }

  h2 { margin: 6px 0 4px; font-size: 15px; font-weight: 600; line-height: 1.35; }
  h2 a { color: var(--text-strong); overflow-wrap: anywhere; }
  h2 a:hover { color: var(--link); }
  h2 a:visited { color: #a5a0d8; }

  .summary {
    margin: 0;
    color: var(--text);
    display: -webkit-box;
    -webkit-line-clamp: 2;
    line-clamp: 2;
    -webkit-box-orient: vertical;
    overflow: hidden;
    overflow-wrap: anywhere;
  }

  .foot { display: flex; flex-wrap: wrap; align-items: center; gap: 4px 10px; margin-top: 8px; font-size: 12px; }
  .products { color: var(--muted); }
  .tag { padding: 0; border: 0; background: none; color: var(--muted); cursor: pointer; font-size: 12px; }
  .tag:hover, .tag.on { color: var(--link); }
</style>
