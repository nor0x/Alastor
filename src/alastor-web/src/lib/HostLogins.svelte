<script lang="ts">
  import { api, type HostLogins } from './api';
  import { on, refreshOn } from './live.svelte';
  import { number } from './format';
  import Time from './ui/Time.svelte';

  // Who logs in to this host over SSH, learned from the agent's login reports. Sources first seen in the last
  // week are marked, and the ones that raised an alert say so.
  let { hostId }: { hostId: string } = $props();

  let data = $state<HostLogins | null>(null);
  const load = async () => (data = await api<HostLogins>(`/api/hosts/${hostId}/logins`).catch(() => data));

  $effect(() => {
    void hostId;
    load();
    const offs = [
      on('eventsCreated', (list: { hostId: string | null; kind: string }[]) => {
        if (list.some((e) => e.hostId === hostId && e.kind.startsWith('auth.login'))) load();
      }),
      refreshOn(['policyChanged'], load, 60_000),
    ];
    return () => offs.forEach((o) => o());
  });

  const week = 7 * 86_400_000;
  const isNew = (iso: string) => Date.now() - new Date(iso).getTime() < week;
</script>

<section class="card">
  <header>
    <h2>SSH logins</h2>
    <span class="hint">
      {#if data && !data.monitor}off (<code>logins.monitor: false</code>)
      {:else if data}{data.alertOnNewSource ? 'alerts on a new user or address' : 'recorded, not alerted'}{#if data.trustedSources.length} · trusted: <span class="mono">{data.trustedSources.join(', ')}</span>{/if}{/if}
    </span>
  </header>
  {#if !data}
    <div class="skeleton-block" style="height:80px"></div>
  {:else if data.sources.length === 0}
    <div class="empty">No logins reported yet. The agent reads sshd's messages from the journal (or auth.log); the first logins it sees are learned without alerts.</div>
  {:else}
    <div class="table-wrap">
      <table class="table">
        <thead><tr><th>User</th><th>From</th><th class="num">Logins</th><th class="hide-sm">Method</th><th>First seen</th><th class="hide-sm">Last</th></tr></thead>
        <tbody>
          {#each data.sources as s (s.user + s.address)}
            <tr>
              <td><strong class:root={s.user === 'root'}>{s.user}</strong></td>
              <td class="mono small">
                <a href="/events?ip={encodeURIComponent(s.address)}">{s.address}</a>
                {#if s.alerted && isNew(s.firstSeenAt)}<span class="pill bad" title="Raised a new-source alert">new</span>
                {:else if isNew(s.firstSeenAt)}<span class="pill info">new</span>{/if}
              </td>
              <td class="num">{number.format(s.logins)}</td>
              <td class="hide-sm small muted">{s.lastMethod}</td>
              <td class="nowrap"><Time iso={s.firstSeenAt} /></td>
              <td class="hide-sm nowrap"><Time iso={s.lastSeenAt} /></td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
</section>

<style>
  .root { color: var(--warn); }
  td .pill { margin-left: 6px; }
</style>
