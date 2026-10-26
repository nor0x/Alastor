<script lang="ts">
  import { api, type About } from '../lib/api';

  let about = $state<About | null>(null);
  $effect(() => {
    api<About>('/api/about').then((a) => (about = a)).catch(() => {});
  });
</script>

<div class="page-head">
  <div>
    <h1>About Alastor</h1>
    {#if about}<p class="sub byline">{#if about.version}<span>Version <span class="mono">{about.version}</span></span>{/if}<span>{about.license} license</span></p>{/if}
  </div>
</div>

{#if about}
  <div class="stack">
    <section class="card card-body">
      <p class="m0">
        Alastor doesn't ship its own security engines. It installs, configures and watches proven open-source tools on each server,
        and brings their results into one dashboard. The code is MIT-licensed. Each bundled tool is installed from your distribution's
        package repositories and keeps its own license, listed below.
      </p>
      <ul class="notes">{#each about.notes as n (n)}<li>{n}</li>{/each}</ul>
    </section>

    <section class="card table-wrap">
      <header><h2>Bundled tools and licenses</h2></header>
      <table class="table">
        <thead><tr><th>Tool</th><th>Capability</th><th>License</th><th>Status</th></tr></thead>
        <tbody>
          {#each about.bundledTools as t (t.id)}
            <tr>
              <td><a class="name" href={t.homepage} target="_blank" rel="noopener noreferrer">{t.name}</a><div class="muted small">{t.description}</div></td>
              <td>{t.capability}</td>
              <td class="mono small nowrap">{t.license}</td>
              <td class="status">
                {#if t.implemented}<span class="pill ok">integrated</span>{:else}<span class="pill muted">planned</span>{/if}
                {#if t.optIn}<span class="pill info">opt-in</span>{/if}
              </td>
            </tr>
          {/each}
          <tr>
            <td>Svelte, Vite, @microsoft/signalr, yaml<div class="muted small">Dashboard libraries</div></td>
            <td>Dashboard</td>
            <td class="mono small nowrap"><span class="lic"><span>MIT</span><span>ISC</span></span></td>
            <td class="status"><span class="pill ok">bundled</span></td>
          </tr>
          <tr>
            <td>Familjen Grotesk, IBM Plex Sans, JetBrains Mono<div class="muted small">Dashboard typefaces</div></td>
            <td>Dashboard</td>
            <td class="mono small nowrap">OFL-1.1</td>
            <td class="status"><span class="pill ok">bundled</span></td>
          </tr>
          <tr>
            <td>.NET, ASP.NET Core, EF Core, Serilog, YamlDotNet, Cronos<div class="muted small">Server and agent libraries</div></td>
            <td>Platform</td>
            <td class="mono small nowrap"><span class="lic"><span>MIT</span><span>Apache-2.0</span></span></td>
            <td class="status"><span class="pill ok">bundled</span></td>
          </tr>
        </tbody>
      </table>
    </section>
  </div>
{/if}

<style>
  .byline { display: flex; flex-wrap: wrap; align-items: center; gap: var(--space-2xs) var(--space-sm); }
  .byline > span + span { padding-left: var(--space-sm); border-left: var(--rule-hair) solid var(--border-strong); }
  .m0 { margin: 0; max-width: 75ch; }
  .notes { display: flex; flex-direction: column; gap: var(--space-2xs); margin: var(--space-sm) 0 0; padding-left: var(--space-md); color: var(--muted); max-width: 75ch; }
  .name { font-weight: 500; }
  .status { white-space: nowrap; }
  .status :global(.pill + .pill) { margin-left: var(--space-2xs); }
  .lic { display: inline-flex; gap: var(--space-xs); }
  .lic > span + span { padding-left: var(--space-xs); border-left: var(--rule-hair) solid var(--border-strong); }
</style>
