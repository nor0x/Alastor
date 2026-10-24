<script lang="ts">
  import { api, errorText, severities, vulnUrl, type FleetVulnerabilities, type Severity as Sev, type VulnDbStatus } from '../lib/api';
  import { bytes } from '../lib/format';
  import { refreshOn } from '../lib/live.svelte';
  import { route } from '../lib/router.svelte';
  import { canWrite } from '../lib/session.svelte';
  import { toast } from '../lib/toast.svelte';
  import Severity from '../lib/ui/Severity.svelte';
  import Time from '../lib/ui/Time.svelte';
  import VulnBadge from '../lib/ui/VulnBadge.svelte';

  const params = new URLSearchParams(route.search);
  let data = $state<FleetVulnerabilities | null>(null);
  let error = $state('');
  let view = $state<'cves' | 'hosts'>(params.get('view') === 'hosts' ? 'hosts' : 'cves');
  let q = $state(params.get('q') ?? '');
  let minSeverity = $state<Sev | ''>((params.get('minSeverity') as Sev) ?? 'High');
  let fixable = $state(params.get('fixable') === '1');
  let kev = $state(params.get('kev') === '1');
  let refreshing = $state('');

  const query = $derived.by(() => {
    const p = new URLSearchParams();
    if (q.trim()) p.set('q', q.trim());
    if (minSeverity) p.set('minSeverity', minSeverity);
    if (fixable) p.set('fixable', 'true');
    if (kev) p.set('kev', 'true');
    return p.toString();
  });

  async function load() {
    try {
      data = await api<FleetVulnerabilities>(`/api/vulnerabilities${query ? `?${query}` : ''}`);
      error = '';
    } catch (e) {
      error = errorText(e);
    }
  }

  // Debounced so typing in the search box doesn't fire a request per key.
  $effect(() => {
    void query;
    const t = setTimeout(load, 200);
    return () => clearTimeout(t);
  });
  $effect(() => refreshOn(['hostUpdated', 'policyChanged'], load, 60_000));

  $effect(() => {
    const p = new URLSearchParams();
    if (view === 'hosts') p.set('view', 'hosts');
    if (q.trim()) p.set('q', q.trim());
    if (minSeverity !== 'High') p.set('minSeverity', minSeverity);
    if (fixable) p.set('fixable', '1');
    if (kev) p.set('kev', '1');
    const s = p.toString();
    history.replaceState(null, '', s ? `/vulnerabilities?${s}` : '/vulnerabilities');
  });

  const scanned = $derived(data?.hosts.filter((h) => h.scannedAt) ?? []);
  const hostsSorted = $derived(
    (data?.hosts ?? []).slice().sort((a, b) => b.kev - a.kev || (b.critical ?? -1) - (a.critical ?? -1) || (b.high ?? -1) - (a.high ?? -1) || a.name.localeCompare(b.name)),
  );
  const noScanner = $derived(data?.hosts.filter((h) => h.availability === 'Disabled' && !h.scannedAt) ?? []);

  async function refreshDb(db: VulnDbStatus) {
    refreshing = db.scanner;
    try {
      await api(`/api/vulnerabilities/db/${db.scanner}/refresh`, { method: 'POST' });
      toast(`The ${db.scanner} database is up to date.`);
      await load();
    } catch (e) {
      toast(errorText(e), 'error');
    } finally {
      refreshing = '';
    }
  }
</script>

<div class="page-head">
  <div>
    <h1>Vulnerabilities</h1>
    <p class="sub">
      {#if data}{scanned.length} of {data.hosts.length} host{data.hosts.length === 1 ? '' : 's'} scanned · {data.totalCves} CVE{data.totalCves === 1 ? '' : 's'} match{/if}
    </p>
  </div>
  <div class="seg" role="group" aria-label="View">
    <button class:on={view === 'cves'} aria-pressed={view === 'cves'} onclick={() => (view = 'cves')}>By CVE</button>
    <button class:on={view === 'hosts'} aria-pressed={view === 'hosts'} onclick={() => (view = 'hosts')}>By host</button>
  </div>
</div>

{#if error}<div class="banner bad" role="alert"><p>{error}</p></div>{/if}

{#if data && noScanner.length && noScanner.length === data.hosts.length}
  <div class="banner info">
    <p>No host has a scanner yet. Install <strong>Trivy</strong> (or Grype) from its vendor's repository on each host; the agent adopts it and scans against a database this server mirrors. Open a host's <strong>CVEs</strong> tab for the exact commands.</p>
  </div>
{/if}

{#if view === 'cves'}
  <div class="filterbar">
    <input class="field grow" type="search" placeholder="CVE, package or title…" bind:value={q} aria-label="Search CVEs" />
    <select class="field" bind:value={minSeverity} aria-label="Minimum severity">
      <option value="">Any severity</option>
      {#each severities as s (s)}<option value={s}>{s}{s === 'Critical' ? '' : ' and above'}</option>{/each}
    </select>
    <label class="check"><input type="checkbox" bind:checked={fixable} /> Fixable</label>
    <label class="check"><input type="checkbox" bind:checked={kev} /> Exploited (KEV)</label>
  </div>

  <div class="card">
    {#if !data}
      <div class="skeleton-block"></div>
    {:else if data.cves.length === 0}
      <div class="empty">{scanned.length ? 'No open vulnerability matches these filters.' : 'No scan results yet.'}</div>
    {:else}
      <div class="table-wrap">
        <table class="table">
          <thead><tr><th>Vulnerability</th><th>Severity</th><th class="num hide-sm">CVSS</th><th class="num">Hosts</th><th class="hide-sm">Packages</th></tr></thead>
          <tbody>
            {#each data.cves as c (c.id)}
              <tr>
                <td class="vuln">
                  <a class="mono" href={vulnUrl(c.id)} target="_blank" rel="noreferrer">{c.id}</a>
                  {#if c.kev}<span class="pill bad" title="In CISA's Known Exploited Vulnerabilities catalog">exploited{c.ransomware ? ' · ransomware' : ''}</span>{/if}
                  {#if c.fixable}<span class="pill ok" title="A fixed package version is available on at least one host">fix available</span>{/if}
                  {#if c.title}<div class="muted small title">{c.title}</div>{/if}
                </td>
                <td><Severity value={c.severity} /></td>
                <td class="num hide-sm">{c.cvss?.toFixed(1) ?? '—'}</td>
                <td class="num hosts">
                  <strong>{c.hostCount}</strong>
                  <div class="small host-list">
                    {#each c.hosts.slice(0, 3) as h (h.id)}<a href="/hosts/{h.id}?tab=vulnerabilities">{h.name}</a>{/each}
                    {#if c.hostCount > 3}<span class="muted">+{c.hostCount - 3}</span>{/if}
                  </div>
                </td>
                <td class="hide-sm mono small">{c.packages.join(', ')}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
      {#if data.totalCves > data.cves.length}<div class="more muted small">Showing the {data.cves.length} most urgent of {data.totalCves}. Narrow the filters to see others.</div>{/if}
    {/if}
  </div>
{:else}
  <div class="card">
    {#if !data}
      <div class="skeleton-block"></div>
    {:else}
      <div class="table-wrap">
        <table class="table">
          <thead><tr><th>Host</th><th>Open CVEs</th><th class="num">Exploited</th><th class="num hide-sm">Fixable</th><th class="hide-sm">Scanner</th><th class="hide-sm">Scanned</th></tr></thead>
          <tbody>
            {#each hostsSorted as h (h.hostId)}
              <tr>
                <td>
                  <a href="/hosts/{h.hostId}?tab=vulnerabilities" class="name">{h.name}</a>
                  {#if h.groupName}<span class="pill info">{h.groupName}</span>{/if}
                  {#if h.error}<div class="small bad-text" title={h.error}>last scan failed</div>{/if}
                </td>
                <td>
                  {#if h.total !== null}<VulnBadge critical={h.critical} high={h.high} total={h.total} /> <span class="muted small">{h.total} total</span>
                  {:else if h.availability === 'Disabled'}<span class="muted small">no scanner installed</span>
                  {:else}<span class="muted">—</span>{/if}
                </td>
                <td class="num">{#if h.kev}<span class="pill bad">{h.kev}</span>{:else}<span class="muted">0</span>{/if}</td>
                <td class="num hide-sm">{h.fixable ?? '—'}</td>
                <td class="hide-sm">{#if h.scanner}<code>{h.scanner}</code>{:else}<span class="muted">—</span>{/if}</td>
                <td class="hide-sm nowrap">{#if h.scannedAt}<Time iso={h.scannedAt} />{:else}<span class="muted">never</span>{/if}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  </div>
{/if}

{#if data}
  <section class="card dbs">
    <header><h2>Vulnerability databases</h2><span class="hint">mirrored by this server; agents never contact the vendors</span></header>
    <div class="db-grid">
      {#each data.databases as db (db.scanner)}
        <div class="db">
          <div class="db-head">
            <strong>{db.scanner === 'trivy' ? 'Trivy' : 'Grype'}</strong>
            {#if db.available}<span class="pill ok">ready</span>
            {:else if db.lastRequestedAt && db.downloadsEnabled}<span class="pill info">downloading…</span>
            {:else}<span class="pill muted">not needed yet</span>{/if}
          </div>
          <dl class="kv small">
            {#if db.builtAt}<dt>Built</dt><dd><Time iso={db.builtAt} /></dd>{/if}
            {#if db.available}<dt>Size</dt><dd>{bytes(db.size)}</dd>{/if}
            {#if db.lastCheckedAt}<dt>Checked</dt><dd><Time iso={db.lastCheckedAt} /></dd>{/if}
            {#if db.lastRequestedAt}<dt>Last agent</dt><dd><Time iso={db.lastRequestedAt} /></dd>{/if}
            <dt>Source</dt><dd class="mono src">{db.source}</dd>
          </dl>
          {#if db.lastError}<p class="small bad-text">{db.lastError}</p>{/if}
          {#if !db.downloadsEnabled}<p class="small muted">Downloads are off (<code>SENTINEL_VULNDBENABLED=false</code>). Place the file in <code>data/vulndb/{db.scanner}/</code>.</p>{/if}
          {#if canWrite() && db.downloadsEnabled}
            <button class="btn small" onclick={() => refreshDb(db)} disabled={refreshing !== ''}>{refreshing === db.scanner ? 'Checking…' : db.available ? 'Check for update' : 'Download now'}</button>
          {/if}
        </div>
      {/each}
    </div>
  </section>
{/if}

<style>
  .check { display: inline-flex; align-items: center; gap: 6px; font-size: 13px; color: var(--muted); white-space: nowrap; }
  .vuln { min-width: 220px; max-width: 460px; }
  .vuln .pill { margin-left: 6px; }
  .title { margin-top: 2px; overflow: hidden; text-overflow: ellipsis; display: -webkit-box; -webkit-line-clamp: 2; line-clamp: 2; -webkit-box-orient: vertical; }
  .hosts { white-space: nowrap; }
  .host-list { display: flex; flex-wrap: wrap; justify-content: flex-end; gap: 0 6px; max-width: 220px; margin-left: auto; white-space: normal; }
  .name { font-weight: 600; margin-right: 6px; }
  .bad-text { color: var(--bad); }
  .more { padding: 8px 16px; border-top: 1px solid var(--border); }
  .dbs { margin-top: 16px; }
  .db-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 12px; padding: 12px 16px 16px; }
  .db { display: flex; flex-direction: column; gap: 8px; padding: 12px; border: 1px solid var(--border); border-radius: var(--radius); background: var(--bg); }
  .db p { margin: 0; }
  .db .btn { align-self: flex-start; }
  .db-head { display: flex; align-items: center; justify-content: space-between; gap: 8px; }
  .kv { display: grid; grid-template-columns: max-content 1fr; gap: 3px 12px; margin: 0; }
  .kv dt { color: var(--muted); }
  .kv dd { margin: 0; overflow-wrap: anywhere; }
  .src { font-size: 11.5px; }
  @media (max-width: 640px) {
    .vuln { min-width: 0; }
  }
</style>
