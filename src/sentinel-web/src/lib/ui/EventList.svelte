<script lang="ts">
  import type { SecurityEvent } from '../api';
  import Severity from './Severity.svelte';
  import Time from './Time.svelte';

  let { events, hostNames = {}, showHost = true, compact = false }: {
    events: SecurityEvent[];
    hostNames?: Record<string, string>;
    showHost?: boolean;
    compact?: boolean;
  } = $props();

  let expanded = $state<string | null>(null);
  const isIp = (s: string | null) => !!s && /^[0-9a-f:.]+(\/\d+)?$/i.test(s) && (s.includes('.') || s.includes(':'));
</script>

<ul class="events" class:compact>
  {#each events as e (e.id)}
    {@const open = expanded === e.id}
    <li class:open>
      <button class="row" aria-expanded={open} onclick={() => (expanded = open ? null : e.id)}>
        <span class="sevcol"><Severity value={e.severity} /></span>
        <span class="main">
          <span class="msg">{e.message}</span>
          <span class="meta">
            <Time iso={e.occurredAt} />
            {#if showHost && e.hostId}<span>· {hostNames[e.hostId] ?? 'host'}</span>{/if}
            <span>· {e.sourceTool}</span>
            <span class="kind">· {e.kind}</span>
            {#if e.alert === 'Notified'}<span class="alert" title="Sent to notification channels">· notified</span>
            {:else if e.alert === 'Suppressed'}<span class="alert" title="A repeat inside the dedup window: counted, not sent">· deduped</span>{/if}
          </span>
        </span>
      </button>
      {#if open}
        <div class="detail">
          <dl>
            {#if e.hostId}<dt>Host</dt><dd><a href="/hosts/{e.hostId}">{hostNames[e.hostId] ?? e.hostId}</a></dd>{/if}
            {#if e.subject}
              <dt>Subject</dt>
              <dd class="mono">
                {e.subject}
                {#if isIp(e.subject)}
                  · <a href="/events?ip={encodeURIComponent(e.subject)}">all events for this IP</a>
                  · <a href="/bans?q={encodeURIComponent(e.subject)}">bans</a>
                {/if}
              </dd>
            {/if}
            <dt>Capability</dt><dd>{e.capability}</dd>
            {#each Object.entries(e.metadata) as [k, v] (k)}<dt>{k}</dt><dd class="mono">{v}</dd>{/each}
          </dl>
          {#if e.raw}<pre class="raw">{e.raw}</pre>{/if}
        </div>
      {/if}
    </li>
  {/each}
</ul>

<style>
  .events { list-style: none; margin: 0; padding: 0; }
  li { border-bottom: 1px solid var(--border); }
  li:last-child { border-bottom: 0; }
  .row {
    display: grid; grid-template-columns: 84px 1fr; gap: 12px; align-items: start; width: 100%;
    padding: 10px 16px; border: 0; background: none; text-align: left; cursor: pointer;
  }
  .row:hover, li.open .row { background: var(--surface-2); }
  .compact .row { padding: 8px 16px; }
  .sevcol { padding-top: 1px; }
  .main { display: flex; flex-direction: column; gap: 2px; min-width: 0; }
  .msg { color: var(--text-strong); overflow-wrap: anywhere; }
  .meta { display: flex; flex-wrap: wrap; gap: 4px; color: var(--muted); font-size: 12px; }
  .kind { font-family: var(--mono); font-size: 11.5px; }
  .alert { font-style: italic; }
  .detail { padding: 4px 16px 14px 112px; background: var(--surface-2); }
  dl { display: grid; grid-template-columns: max-content 1fr; gap: 4px 16px; margin: 0 0 8px; font-size: 12.5px; }
  dt { color: var(--muted); }
  dd { margin: 0; overflow-wrap: anywhere; }
  .raw { padding: 8px 10px; border-radius: 6px; background: var(--bg); border: 1px solid var(--border); color: var(--muted); }
  @media (max-width: 640px) {
    .row { grid-template-columns: 1fr; gap: 4px; }
    .detail { padding-left: 16px; }
  }
</style>
