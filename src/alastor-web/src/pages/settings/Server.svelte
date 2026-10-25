<script lang="ts">
  import { api } from '../../lib/api';

  interface Setting { group: string; key: string; envVar: string; value: string; description: string }
  let settings = $state<Setting[]>([]);

  $effect(() => {
    api<Setting[]>('/api/system/settings').then((s) => (settings = s)).catch(() => {});
  });

  const groups = $derived([...new Set(settings.map((s) => s.group))]);
</script>

<section class="card">
  <header><h2>Server configuration</h2><span class="hint">read-only</span></header>
  <p class="muted small intro">
    Server-wide settings come from environment variables (or the <code>Alastor</code> section of appsettings.json) and apply after a restart.
    Durations use the policy format (<code>30s</code>, <code>5m</code>, <code>7d</code>); bad values stop the server at startup with a clear message.
    Per-host timings (heartbeat, scans, update checks) live in the <a href="/policies/global">policy</a> instead, so they can differ per group or host.
  </p>
  {#each groups as g (g)}
    <h3>{g}</h3>
    <div class="table-wrap">
      <table class="table">
        <tbody>
          {#each settings.filter((s) => s.group === g) as s (s.key)}
            <tr>
              <td class="k"><span class="mono small">{s.envVar}</span><div class="muted small">{s.description}</div></td>
              <td class="mono v">{s.value}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/each}
</section>

<style>
  .intro { margin: 0; padding: 12px 16px; }
  h3 { margin: 8px 16px 0; font-size: 13px; color: var(--muted); font-weight: 600; }
  .k { width: 65%; }
  .v { overflow-wrap: anywhere; }
</style>
