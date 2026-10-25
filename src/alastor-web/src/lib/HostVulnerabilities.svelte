<script lang="ts">
  import { api, errorText, severities, vulnUrl, type Command, type HostVulnerabilities, type Severity as Sev, type VulnFinding } from './api';
  import { layerValue, setLayerKey } from './baseline';
  import { on, refreshOn } from './live.svelte';
  import { canWrite } from './session.svelte';
  import { toast } from './toast.svelte';
  import { confirm } from './ui/confirm.svelte';
  import CopyButton from './ui/CopyButton.svelte';
  import Severity from './ui/Severity.svelte';
  import Time from './ui/Time.svelte';

  let { hostId, isOnline, osId }: { hostId: string; isOnline: boolean; osId: string } = $props();

  const osFamily = $derived(osId === 'alpine' ? 'Alpine' : /^(rhel|rocky|almalinux|centos|fedora|amzn|ol)$/.test(osId) ? 'RedHat' : 'Debian');

  let data = $state<HostVulnerabilities | null>(null);
  let error = $state('');
  let scanning = $state(false);
  let q = $state('');
  let minSeverity = $state<Sev | ''>('');
  let fixableOnly = $state(false);
  let showAccepted = $state(false);
  let kind = $state<'' | 'os' | 'lang'>('');
  let limit = $state(100);

  const osTypes = new Set(['deb', 'rpm', 'apk']);
  const rank: Record<Sev, number> = { Info: 0, Low: 1, Medium: 2, High: 3, Critical: 4 };

  async function load() {
    try {
      const prev = data?.lastAttemptAt;
      data = await api<HostVulnerabilities>(`/api/hosts/${hostId}/vulnerabilities`);
      error = '';
      if (scanning && data.lastAttemptAt !== prev) scanning = false;
    } catch (e) {
      error = errorText(e);
    }
  }

  $effect(() => {
    void hostId;
    load();
    const offs = [
      on('hostUpdated', (h: { id: string }) => { if (h.id === hostId) load(); }),
      refreshOn(['policyChanged'], load, 60_000),
    ];
    return () => offs.forEach((o) => o());
  });

  interface Group {
    id: string;
    severity: Sev;
    cvss: number | null;
    title: string | null;
    kev: boolean;
    ransomware: boolean;
    accepted: boolean;
    fixable: boolean;
    firstSeenAt: string;
    packages: VulnFinding[];
  }

  // One row per vulnerability: an OpenSSL CVE in libssl3 and openssl is one thing to fix.
  const groups = $derived.by(() => {
    const map = new Map<string, Group>();
    for (const f of data?.findings ?? []) {
      let g = map.get(f.id);
      if (!g) {
        g = { id: f.id, severity: f.severity, cvss: f.cvss, title: f.title, kev: f.kev, ransomware: f.ransomware, accepted: f.accepted, fixable: false, firstSeenAt: f.firstSeenAt, packages: [] };
        map.set(f.id, g);
      }
      g.packages.push(f);
      if (rank[f.severity] > rank[g.severity]) g.severity = f.severity;
      if ((f.cvss ?? 0) > (g.cvss ?? 0)) g.cvss = f.cvss;
      g.title ??= f.title;
      g.fixable ||= f.fix === 'Fixable';
      if (f.firstSeenAt < g.firstSeenAt) g.firstSeenAt = f.firstSeenAt;
    }
    return [...map.values()].sort((a, b) => Number(b.kev) - Number(a.kev) || rank[b.severity] - rank[a.severity] || Number(b.fixable) - Number(a.fixable)
      || (b.cvss ?? 0) - (a.cvss ?? 0) || a.id.localeCompare(b.id));
  });
  const open = $derived(groups.filter((g) => !g.accepted));
  // The headline is about the host's own packages, like the server's counts: updating the host doesn't fix an image.
  const hostOpen = $derived(open.filter((g) => g.packages.some((p) => !p.image)));
  const counts = $derived(Object.fromEntries(severities.map((s) => [s, hostOpen.filter((g) => g.severity === s).length])) as Record<Sev, number>);
  const kevOpen = $derived(open.filter((g) => g.kev));
  const fixableCount = $derived(hostOpen.filter((g) => g.packages.some((p) => !p.image && p.fix === 'Fixable')).length);
  const acceptedCount = $derived(groups.length - open.length);
  const ignoredTotal = $derived(Object.values(data?.ignored ?? {}).reduce((a, b) => a + b, 0));

  // "" = everything, "host" = the host's own packages, else one container image.
  let source = $state('');
  const imageNames = $derived([...new Set((data?.findings ?? []).map((f) => f.image).filter((i): i is string => !!i))].sort());

  const filtered = $derived.by(() => {
    const needle = q.trim().toLowerCase();
    return groups.filter((g) => {
      if (g.accepted && !showAccepted) return false;
      if (minSeverity && rank[g.severity] < rank[minSeverity]) return false;
      if (fixableOnly && !g.fixable) return false;
      if (source === 'host' && g.packages.every((p) => p.image)) return false;
      if (source && source !== 'host' && !g.packages.some((p) => p.image === source)) return false;
      if (kind === 'os' && !g.packages.some((p) => osTypes.has(p.pkgType))) return false;
      if (kind === 'lang' && g.packages.every((p) => osTypes.has(p.pkgType))) return false;
      if (needle && !(g.id.toLowerCase().includes(needle) || (g.title ?? '').toLowerCase().includes(needle) || g.packages.some((p) => p.package.toLowerCase().includes(needle) || (p.path ?? '').toLowerCase().includes(needle)))) return false;
      return true;
    });
  });
  $effect(() => {
    void q; void minSeverity; void fixableOnly; void showAccepted; void kind; void source;
    limit = 100;
  });

  const noScanner = $derived(data !== null && !data.scanner.active);

  async function scan() {
    try {
      await api<Command>(`/api/hosts/${hostId}/actions/scan-vulnerabilities`, { method: 'POST' });
      scanning = true;
      toast(isOnline ? 'Scan queued. A full scan takes a minute or two; the first one also downloads the database.' : 'The host is offline; it scans when the agent reconnects.');
      setTimeout(() => (scanning = false), 30 * 60_000);
    } catch (e) {
      toast(errorText(e), 'error');
    }
  }

  async function hostIgnoreList(): Promise<string[]> {
    const v = await layerValue({ scope: 'host', id: hostId }, ['vulnerabilities', 'ignore']);
    return Array.isArray(v) ? v.map(String) : [];
  }

  async function accept(g: Group) {
    const ok = await confirm(`Accept the risk of ${g.id}?`,
      'It stays listed on this host, but no longer counts toward its totals or raises alerts. You can undo this at any time.',
      { confirmLabel: 'Accept risk' });
    if (!ok) return;
    try {
      const list = await hostIgnoreList();
      if (!list.includes(g.id)) await setLayerKey({ scope: 'host', id: hostId }, ['vulnerabilities', 'ignore'], [...list, g.id], `Vulnerabilities: accept ${g.id}`);
      toast('Accepted for this host.');
    } catch (e) {
      toast(errorText(e), 'error');
    }
  }

  async function unaccept(g: Group) {
    try {
      const list = await hostIgnoreList();
      if (!list.includes(g.id)) {
        toast(`${g.id} is accepted in the group or global policy. Change it there.`, 'error');
        return;
      }
      const rest = list.filter((id) => id !== g.id);
      await setLayerKey({ scope: 'host', id: hostId }, ['vulnerabilities', 'ignore'], rest.length ? rest : undefined, `Vulnerabilities: stop accepting ${g.id}`);
      toast('This host counts it again.');
    } catch (e) {
      toast(errorText(e), 'error');
    }
  }

  const fixText = (p: VulnFinding) =>
    p.fix === 'Fixable' ? (p.fixed ?? 'fixed version available') : p.fix === 'WontFix' ? "vendor won't fix" : p.fix === 'NoFix' ? 'no fix yet' : 'unknown';

  const installCommands = $derived(
    osFamily === 'RedHat'
      ? [
          "printf '[trivy]\\nname=Trivy repository\\nbaseurl=https://aquasecurity.github.io/trivy-repo/rpm/releases/$basearch/\\ngpgcheck=1\\nenabled=1\\ngpgkey=https://aquasecurity.github.io/trivy-repo/rpm/public.key\\n' | sudo tee /etc/yum.repos.d/trivy.repo",
          'sudo dnf install -y trivy',
        ]
      : osFamily === 'Alpine'
        ? ['apk add trivy   # community repository; the agent does this itself when agent.autoInstall is on']
        : [
            'sudo apt-get install -y wget gnupg',
            'wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor | sudo tee /usr/share/keyrings/trivy.gpg > /dev/null',
            'echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" | sudo tee /etc/apt/sources.list.d/trivy.list',
            'sudo apt-get update && sudo apt-get install -y trivy',
          ],
  );
</script>

{#if error && !data}
  <div class="banner bad" role="alert"><p>Couldn't load vulnerabilities: {error}</p></div>
{:else if !data}
  <div class="skeleton-block"></div>
{:else}
  <div class="stack">
    <section class="card summary">
      <div class="figure">
        <span class="big" class:bad-text={counts.Critical + counts.High > 0}>{data.scannedAt ? counts.Critical + counts.High : '—'}</span>
        <span class="muted small">critical &amp; high</span>
      </div>
      <div class="counts">
        {#if data.scannedAt}
          {#each severities.filter((s) => s !== 'Info' || counts.Info) as s (s)}
            <button class="chip" class:on={minSeverity === s} onclick={() => (minSeverity = minSeverity === s ? '' : s)} title="Show {s} and above">
              <Severity value={s} /> <strong class="n">{counts[s]}</strong>
            </button>
          {/each}
          <span><strong class="n">{fixableCount}</strong> fixable by updating</span>
          {#if acceptedCount}<span class="muted">{acceptedCount} accepted</span>{/if}
        {/if}
      </div>
      <div class="meta">
        <span class="muted small">
          {#if data.scanner.active}<code>{data.scanner.active}</code>{data.scanner.version ? ` ${data.scanner.version}` : ''}{/if}
          {#if data.dbUpdatedAt} · database <Time iso={data.dbUpdatedAt} />{/if}
          {#if data.scannedAt} · scanned <Time iso={data.scannedAt} />{:else} · not scanned yet{/if}
        </span>
        {#if canWrite() && !noScanner}<button class="btn small" onclick={scan} disabled={scanning}>{scanning ? 'Scanning…' : 'Scan now'}</button>{/if}
      </div>
    </section>

    {#if noScanner}
      <section class="card pad stack-sm">
        <h2>No scanner on this host</h2>
        <p>
          Alastor scans with <a href="https://trivy.dev" target="_blank" rel="noreferrer">Trivy</a> or
          <a href="https://github.com/anchore/grype" target="_blank" rel="noreferrer">Grype</a>. Most distributions don't package either,
          so the agent adopts one you install from its vendor's repository. It never downloads binaries itself, and its database comes from
          this server, so the host doesn't contact the vendor again after installing.
        </p>
        <div class="commands">
          {#each installCommands as cmd, i (i)}
            <div class="cmd"><code>{cmd}</code><CopyButton text={cmd.replace(/\s+#.*$/, '')} /></div>
          {/each}
        </div>
        <p class="muted small">The agent picks it up within a minute and scans right away. Or choose Grype with <code>vulnerabilities.scanner: grype</code>.</p>
      </section>
    {/if}

    {#if data.lastScanSucceeded === false}
      <div class="banner bad" role="alert">
        <p><strong>The last scan failed</strong>{#if data.lastAttemptAt} (<Time iso={data.lastAttemptAt} />){/if}: <span class="mono small">{data.lastScanError}</span>{data.scannedAt ? ' The list below is from the last successful scan.' : ''}</p>
      </div>
    {/if}

    {#if kevOpen.length}
      <div class="banner bad">
        <p>
          <strong>{kevOpen.length} vulnerabilit{kevOpen.length === 1 ? 'y is' : 'ies are'} being exploited in the wild</strong> (CISA's Known Exploited Vulnerabilities catalog):
          {kevOpen.slice(0, 5).map((g) => g.id).join(', ')}{kevOpen.length > 5 ? ' …' : ''}.
          {kevOpen.some((g) => g.fixable) ? 'Install updates first; these are listed at the top.' : 'No fixed package is available yet; consider limiting exposure of the affected service.'}
        </p>
      </div>
    {/if}

    {#if data.scannedAt}
      {#if data.images?.length}
        <section class="card">
          <header><h2>Container images</h2><span class="hint">scanned locally with the host; host updates don't reach them</span></header>
          <div class="table-wrap">
            <table class="table">
              <thead><tr><th>Image</th><th class="hide-sm">Containers</th><th class="num">Findings</th></tr></thead>
              <tbody>
                {#each data.images as i (i.runtime + i.image)}
                  <tr>
                    <td><span class="mono small">{i.image}</span> <span class="muted small">{i.runtime}</span>{#if i.error}<div class="small bad-text">{i.error}</div>{/if}</td>
                    <td class="hide-sm small">{i.containers.join(', ')}</td>
                    <td class="num">{#if i.error}<span class="muted">—</span>{:else}<button class="btn ghost small" onclick={() => (source = i.image)}>{i.findings}</button>{/if}</td>
                  </tr>
                {/each}
              </tbody>
            </table>
          </div>
        </section>
      {/if}

      <section class="card">
        <header>
          <h2>Vulnerabilities</h2>
          <span class="hint">{filtered.length} of {groups.length}</span>
        </header>
        <div class="filterbar pad-x">
          <input class="field grow" type="search" placeholder="CVE, package, path…" bind:value={q} aria-label="Search vulnerabilities" />
          <select class="field" bind:value={minSeverity} aria-label="Minimum severity">
            <option value="">Any severity</option>
            {#each severities as s (s)}<option value={s}>{s}{s === 'Critical' ? '' : ' and above'}</option>{/each}
          </select>
          {#if imageNames.length}
            <select class="field" bind:value={source} aria-label="Source">
              <option value="">Host and containers</option>
              <option value="host">Host packages</option>
              {#each imageNames as i (i)}<option value={i}>Image {i}</option>{/each}
            </select>
          {/if}
          <select class="field" bind:value={kind} aria-label="Package kind">
            <option value="">OS and language packages</option>
            <option value="os">OS packages</option>
            <option value="lang">Language packages</option>
          </select>
          <label class="check"><input type="checkbox" bind:checked={fixableOnly} /> Fixable only</label>
          {#if acceptedCount}<label class="check"><input type="checkbox" bind:checked={showAccepted} /> Show accepted</label>{/if}
        </div>
        {#if filtered.length === 0}
          <div class="empty">{groups.length ? 'Nothing matches these filters.' : 'No known vulnerabilities in the installed packages. 🎉'}</div>
        {:else}
          <div class="table-wrap">
            <table class="table">
              <thead><tr><th>Vulnerability</th><th>Severity</th><th class="num hide-sm">CVSS</th><th>Package → fix</th>{#if canWrite()}<th class="hide-sm"></th>{/if}</tr></thead>
              <tbody>
                {#each filtered.slice(0, limit) as g (g.id)}
                  <tr class:accepted={g.accepted}>
                    <td class="vuln">
                      <a class="mono" href={vulnUrl(g.id)} target="_blank" rel="noreferrer">{g.id}</a>
                      {#if g.kev}<span class="pill bad" title="In CISA's Known Exploited Vulnerabilities catalog{g.ransomware ? '; used in ransomware campaigns' : ''}">exploited{g.ransomware ? ' · ransomware' : ''}</span>{/if}
                      {#if g.accepted}<span class="pill muted">accepted</span>{/if}
                      {#if g.title}<div class="muted small title">{g.title}</div>{/if}
                    </td>
                    <td><Severity value={g.severity} /></td>
                    <td class="num hide-sm">{g.cvss?.toFixed(1) ?? '—'}</td>
                    <td class="pkgs">
                      {#each g.packages.slice(0, 4) as p, i (i)}
                        <div class="pkg" title={p.path ?? ''}>
                          <span class="mono">{p.package}</span>
                          <span class="mono small muted">{p.installed}</span>
                          <span class="small" class:ok-text={p.fix === 'Fixable'} class:muted={p.fix !== 'Fixable'}>→ {fixText(p)}</span>
                          {#if !osTypes.has(p.pkgType)}<span class="pill muted">{p.pkgType}</span>{/if}
                          {#if p.image}<span class="pill info" title="In container image {p.image}: rebuild or pull a newer image to fix">{p.image}</span>{/if}
                        </div>
                      {/each}
                      {#if g.packages.length > 4}<div class="muted small">and {g.packages.length - 4} more</div>{/if}
                    </td>
                    {#if canWrite()}
                      <td class="hide-sm nowrap">
                        {#if g.accepted}<button class="btn ghost small" onclick={() => unaccept(g)}>Stop accepting</button>
                        {:else}<button class="btn ghost small" onclick={() => accept(g)}>Accept risk</button>{/if}
                      </td>
                    {/if}
                  </tr>
                {/each}
              </tbody>
            </table>
          </div>
          {#if filtered.length > limit}
            <div class="more"><button class="btn ghost small" onclick={() => (limit += 200)}>Show more ({filtered.length - limit} left)</button></div>
          {/if}
        {/if}
      </section>

      <section class="card pad stack-sm">
        <h2 class="h-sm">Scan settings</h2>
        <p class="muted small">
          {data.scanner.setting === 'auto' ? 'Scanner: Trivy if installed, else Grype' : `Scanner: ${data.scanner.setting}`} ·
          {data.scanner.languagePackages ? 'OS and language packages' : 'OS packages only'} ·
          alerts on new fixable findings at <strong>{data.scanner.alertSeverity}</strong>{data.scanner.alertSeverity === 'off' ? '' : ' and above'} ·
          schedule <code>{data.schedule.value}</code>{data.schedule.isDefault ? ' (default)' : ''}.
          Known-exploited CVEs always alert.
        </p>
        {#if ignoredTotal}
          <p class="muted small">
            Not listed: {Object.entries(data.ignored).map(([p, n]) => `${n} in ${p}`).join(', ')} (<code>vulnerabilities.ignorePackages</code>{data.ignored['linux-libc-dev'] ? '; kernel headers carry every kernel CVE, but no kernel code runs from them' : ''}).
          </p>
        {/if}
        {#if data.truncated}<p class="note small">This host had more findings than a report holds; the least severe were left out.</p>{/if}
        <p class="small"><a href="/policies/host/{hostId}">Change for this host</a> · <a href="/policies/global">for all hosts</a></p>
      </section>
    {:else if !noScanner && data.lastScanSucceeded !== false}
      <div class="empty empty-dashed">
        No scan results yet. The agent scans on start and then on <code>{data.schedule.value}</code>. The first scan waits for this server to download the
        vulnerability database (100 to 200 MB, once for the whole fleet).
      </div>
    {/if}
  </div>
{/if}

<style>
  .summary { display: flex; flex-wrap: wrap; align-items: center; gap: 16px 32px; padding: 16px; }
  .figure { display: flex; flex-direction: column; min-width: 96px; }
  .figure .big { font-size: 34px; font-weight: 600; line-height: 1; font-variant-numeric: tabular-nums; color: var(--text-strong); }
  .figure .big.bad-text { color: var(--bad); }
  .counts { display: flex; flex-wrap: wrap; align-items: center; gap: 6px 16px; color: var(--muted); }
  .counts .n { color: var(--text-strong); font-variant-numeric: tabular-nums; }
  .chip { display: inline-flex; align-items: center; gap: 6px; padding: 2px 6px; border-radius: 6px; border: 1px solid transparent; background: none; color: inherit; cursor: pointer; font: inherit; }
  .chip:hover { background: var(--surface-2); }
  .chip.on { border-color: var(--border-strong, var(--border)); background: var(--surface-2); }
  .meta { margin-left: auto; display: flex; flex-wrap: wrap; align-items: center; gap: 10px; }
  .pad { padding: 14px 16px 16px; }
  .pad-x { padding: 0 16px; }
  .stack-sm { display: flex; flex-direction: column; gap: 8px; }
  .stack-sm p, .stack-sm h2 { margin: 0; }
  .h-sm { font-size: 14px; }
  .check { display: inline-flex; align-items: center; gap: 6px; font-size: 13px; color: var(--muted); white-space: nowrap; }
  .vuln { min-width: 200px; max-width: 420px; }
  .vuln .pill { margin-left: 6px; }
  .title { margin-top: 2px; overflow: hidden; text-overflow: ellipsis; display: -webkit-box; -webkit-line-clamp: 2; line-clamp: 2; -webkit-box-orient: vertical; }
  .pkgs { min-width: 220px; }
  .pkg { display: flex; flex-wrap: wrap; align-items: baseline; gap: 2px 8px; }
  .pkg + .pkg { margin-top: 3px; }
  .ok-text { color: var(--ok); }
  tr.accepted td { opacity: 0.6; }
  .more { padding: 8px 16px; border-top: 1px solid var(--border); }
  .note { color: var(--warn); }
  .commands { display: flex; flex-direction: column; gap: 6px; }
  .cmd { display: flex; align-items: flex-start; gap: 8px; }
  .cmd code { flex: 1; min-width: 0; padding: 6px 8px; border-radius: 6px; background: var(--surface-2); font-size: 12px; overflow-wrap: anywhere; white-space: pre-wrap; }
  @media (max-width: 640px) {
    .meta { margin-left: 0; }
    .vuln { min-width: 0; }
    .pkgs { min-width: 0; }
  }
</style>
