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
            {#if showHost && e.hostId}<span class="host">{hostNames[e.hostId] ?? 'host'}</span>{/if}
            <span>{e.sourceTool}</span>
            <span class="kind">{e.kind}</span>
            {#if e.alert === 'Notified'}<span class="alert" title="Sent to notification channels">notified</span>
            {:else if e.alert === 'Suppressed'}<span class="alert" title="A repeat inside the dedup window: counted, not sent">deduped</span>{/if}
          </span>
        </span>
      </button>
      {#if open}
        <div class="detail">
          <dl class="kv">
            {#if e.hostId}<dt>Host</dt><dd><a href="/hosts/{e.hostId}">{hostNames[e.hostId] ?? e.hostId}</a></dd>{/if}
            {#if e.subject}
              <dt>Subject</dt>
              <dd class="mono">
                {e.subject}
                {#if isIp(e.subject)}
                  <a class="sub-link" href="/events?ip={encodeURIComponent(e.subject)}">all events for this IP</a>
                  <a class="sub-link" href="/bans?q={encodeURIComponent(e.subject)}">bans</a>
                {/if}
              </dd>
            {/if}
            <dt>Capability</dt><dd>{e.capability}</dd>
            {#each Object.entries(e.metadata) as [k, v] (k)}<dt>{k}</dt><dd class="mono">{v}</dd>{/each}
          </dl>
          {#if e.raw}<pre class="code-block raw">{e.raw}</pre>{/if}
        </div>
      {/if}
    </li>
  {/each}
</ul>

<style>
  .events { list-style: none; margin: 0; padding: 0; }
  li { border-bottom: var(--rule-hair) solid var(--border); }
  li:last-child { border-bottom: 0; }
  .row {
    display: grid; grid-template-columns: 96px minmax(0, 1fr); gap: var(--space-sm); align-items: start; width: 100%;
    padding: var(--space-sm) var(--space-md); border: 0; background: none; text-align: left; cursor: pointer;
  }
  .row:hover { background: var(--color-paper-2); }
  .row:active { background: var(--color-paper-3); }
  .row:focus-visible { outline-offset: -2px; }
  li.open .row { background: var(--color-paper-2); }
  .compact .row { padding: var(--space-xs) var(--space-md); }
  .sevcol { padding-top: var(--space-3xs); }
  .main { display: flex; flex-direction: column; gap: var(--space-2xs); min-width: 0; }
  .msg { color: var(--text-strong); overflow-wrap: anywhere; }
  .meta { display: flex; flex-wrap: wrap; align-items: center; row-gap: var(--space-2xs); color: var(--muted); font-size: var(--text-sm); }
  .meta > :global(*) + :global(*) { margin-left: var(--space-xs); padding-left: var(--space-xs); box-shadow: inset 1px 0 0 var(--border-strong); }
  .host { color: var(--color-ink-2); }
  .kind { font-family: var(--mono); font-size: var(--text-code); }
  .alert { color: var(--color-ink-2); }
  .detail { display: flex; flex-direction: column; gap: var(--space-sm); padding: var(--space-2xs) var(--space-md) var(--space-md) calc(96px + var(--space-sm) + var(--space-md)); background: var(--color-paper-2); }
  .kv { font-size: var(--text-sm); }
  .sub-link { margin-left: var(--space-sm); font-family: var(--font-body); }
  @media (max-width: 640px) {
    .row { grid-template-columns: minmax(0, 1fr); gap: var(--space-2xs); }
    .detail { padding-left: var(--space-md); }
  }
</style>
