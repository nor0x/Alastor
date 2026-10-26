<script lang="ts">
  import type { FeedItem } from './api';
  import { fullDate, timeAgo } from './format';
  import Icon from './ui/Icon.svelte';

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
        <Icon name="alert" size={14} />
        Actively exploited
      </span>
    {/if}
  </div>

  <h2><a href={item.url} target="_blank" rel="noopener noreferrer">{item.title}</a></h2>

  {#if item.summary}<p class="summary">{item.summary}</p>{/if}

  {#if tags.length || item.products.length}
    <div class="foot">
      {#if item.products.length}
        <span class="products">{#each item.products.slice(0, 3) as p, i (i)}<span class="mono">{p}</span>{/each}</span>
      {/if}
      {#if tags.length}
        <span class="tags">
          {#each tags as tag (tag)}
            <button class="tag" class:on={activeTags.some((t) => t.toLowerCase() === tag.toLowerCase())} onclick={() => onTag(tag)}>#{tag}</button>
          {/each}
        </span>
      {/if}
    </div>
  {/if}
</li>

<style>
  .row {
    display: flex;
    flex-direction: column;
    gap: var(--space-2xs);
    padding: var(--space-sm) var(--space-md);
    border-bottom: var(--rule-hair) solid var(--border);
    background: var(--surface);
  }
  .row:last-child { border-bottom: 0; }
  .row:hover { background: var(--color-paper-2); }
  .row.exploited { background: color-mix(in oklab, var(--exploited-bg) 55%, var(--surface)); }
  .row.exploited:hover { background: var(--exploited-bg); }

  .meta { display: flex; flex-wrap: wrap; align-items: center; gap: var(--space-2xs) var(--space-sm); font-size: var(--text-sm); color: var(--muted); }
  .source {
    padding: 0 var(--space-xs);
    border-radius: 4px;
    background: var(--color-paper-3);
    color: var(--color-ink-2);
    font-family: var(--font-display);
    font-weight: 500;
    font-size: var(--text-xs);
    line-height: 20px;
  }
  .source.cve { background: var(--color-accent-wash); color: var(--color-accent-deep); }
  time { font-variant-numeric: tabular-nums; }

  .unscored { color: var(--muted); }

  .kev {
    display: inline-flex;
    align-items: center;
    gap: var(--space-2xs);
    color: var(--exploited);
    font-weight: 500;
  }

  h2 { max-width: none; margin: var(--space-3xs) 0 0; font-size: var(--text-lg); font-weight: 600; line-height: 1.3; letter-spacing: -0.01em; }
  h2 a { color: var(--text-strong); overflow-wrap: anywhere; }
  h2 a:hover { color: var(--link); }
  h2 a:visited { color: var(--color-ink-2); }

  .summary {
    margin: 0;
    max-width: 90ch;
    color: var(--text);
    display: -webkit-box;
    -webkit-line-clamp: 2;
    line-clamp: 2;
    -webkit-box-orient: vertical;
    overflow: hidden;
    overflow-wrap: anywhere;
  }

  .foot { display: flex; flex-wrap: wrap; align-items: center; gap: var(--space-2xs) var(--space-sm); margin-top: var(--space-2xs); font-size: var(--text-xs); }
  .products { display: inline-flex; flex-wrap: wrap; gap: var(--space-2xs) var(--space-xs); color: var(--muted); }
  .products .mono { font-size: var(--text-xs); }
  .products > span + span { padding-left: var(--space-xs); border-left: var(--rule-hair) solid var(--color-rule-2); }
  .tags { display: inline-flex; flex-wrap: wrap; gap: var(--space-2xs) var(--space-xs); }
  .tag { padding: 0; border: 0; background: none; color: var(--muted); cursor: pointer; font-size: var(--text-xs); }
  .tag:hover, .tag.on { color: var(--link); }
  .tag:hover { text-decoration: underline; }
  .tag:active { color: var(--color-accent-deep); }
</style>
