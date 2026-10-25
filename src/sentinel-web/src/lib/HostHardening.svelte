<script lang="ts">
  import { api, errorText, lynisUrl, type Command, type HardeningItem, type HostHardening } from './api';
  import { layerValue, setLayerKey } from './baseline';
  import { indexTone, lynisNotes } from './hardening';
  import { on, refreshOn } from './live.svelte';
  import { canWrite } from './session.svelte';
  import { toast } from './toast.svelte';
  import { confirm } from './ui/confirm.svelte';
  import CopyButton from './ui/CopyButton.svelte';
  import Time from './ui/Time.svelte';

  let { hostId, isOnline, osId }: { hostId: string; isOnline: boolean; osId: string } = $props();

  let data = $state<HostHardening | null>(null);
  let error = $state('');
  let auditing = $state(false);
  let showAccepted = $state(false);
  let q = $state('');

  async function load() {
    try {
      const prev = data?.lastAttemptAt;
      data = await api<HostHardening>(`/api/hosts/${hostId}/hardening`);
      error = '';
      if (auditing && data.lastAttemptAt !== prev) auditing = false;
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

  const items = $derived(data?.items ?? []);
  const open = $derived(items.filter((i) => !i.accepted));
  // Counted per test id, like the checklist.
  const warningIds = $derived(new Set(open.filter((i) => i.kind === 'Warning').map((i) => i.testId)));
  const suggestionIds = $derived(new Set(open.filter((i) => i.kind === 'Suggestion' && !warningIds.has(i.testId)).map((i) => i.testId)));
  const acceptedCount = $derived(new Set(items.filter((i) => i.accepted).map((i) => i.testId)).size);

  /** One checklist row per test id: FILE-6310 reports once per mount point, but it's one thing to decide about. */
  interface Row {
    testId: string;
    category: string;
    warning: boolean;
    accepted: boolean;
    entries: HardeningItem[];
    firstSeenAt: string;
  }

  const rows = $derived.by(() => {
    const map = new Map<string, Row>();
    for (const i of items) {
      let r = map.get(i.testId);
      if (!r) map.set(i.testId, (r = { testId: i.testId, category: i.category, warning: false, accepted: i.accepted, entries: [], firstSeenAt: i.firstSeenAt }));
      r.warning ||= i.kind === 'Warning';
      // Lynis sometimes repeats a warning as a suggestion with the same text.
      if (!r.entries.some((e) => e.text === i.text && e.details === i.details)) r.entries.push(i);
      if (i.firstSeenAt < r.firstSeenAt) r.firstSeenAt = i.firstSeenAt;
    }
    return [...map.values()];
  });

  const groups = $derived.by(() => {
    const needle = q.trim().toLowerCase();
    const visible = rows.filter((r) => (showAccepted || !r.accepted)
      && (!needle || r.testId.toLowerCase().includes(needle) || r.category.toLowerCase().includes(needle)
        || r.entries.some((e) => `${e.text} ${e.details ?? ''} ${e.solution ?? ''}`.toLowerCase().includes(needle))));
    const map = new Map<string, Row[]>();
    for (const r of visible) map.set(r.category, [...(map.get(r.category) ?? []), r]);
    // Categories with warnings first, then the biggest.
    return [...map.entries()]
      .map(([category, list]) => ({ category, rows: list.sort((a, b) => Number(b.warning) - Number(a.warning) || a.testId.localeCompare(b.testId)) }))
      .sort((a, b) => Number(b.rows.some((r) => r.warning)) - Number(a.rows.some((r) => r.warning)) || b.rows.length - a.rows.length || a.category.localeCompare(b.category));
  });
  const visibleCount = $derived(groups.reduce((n, g) => n + g.rows.length, 0));

  const notInstalled = $derived(data !== null && !data.tool.installed && !data.auditedAt);
  const installCommand = $derived(
    osId === 'alpine' ? 'apk add lynis'
      : /^(rhel|rocky|almalinux|centos|ol)$/.test(osId) ? 'sudo dnf install -y epel-release && sudo dnf install -y lynis'
        : /^(fedora|amzn)$/.test(osId) ? 'sudo dnf install -y lynis' : 'sudo apt-get install -y lynis',
  );

  async function audit() {
    try {
      await api<Command>(`/api/hosts/${hostId}/actions/run-audit`, { method: 'POST' });
      auditing = true;
      toast(isOnline ? 'Audit queued. Lynis takes a few minutes; it runs at low priority.' : 'The host is offline; it audits when the agent reconnects.');
      setTimeout(() => (auditing = false), 60 * 60_000);
    } catch (e) {
      toast(errorText(e), 'error');
    }
  }

  async function hostIgnoreList(): Promise<string[]> {
    const v = await layerValue({ scope: 'host', id: hostId }, ['hardening', 'ignore']);
    return Array.isArray(v) ? v.map(String) : [];
  }

  async function accept(r: Row) {
    const ok = await confirm(`Accept ${r.testId}?`,
      'It stays in the checklist, marked accepted, but no longer counts for this host or appears in the fleet view. The hardening index is Lynis\'s own and does not change.',
      { confirmLabel: 'Accept' });
    if (!ok) return;
    try {
      const list = await hostIgnoreList();
      if (!list.includes(r.testId)) await setLayerKey({ scope: 'host', id: hostId }, ['hardening', 'ignore'], [...list, r.testId], `Hardening: accept ${r.testId}`);
      toast('Accepted for this host.');
    } catch (e) {
      toast(errorText(e), 'error');
    }
  }

  async function unaccept(r: Row) {
    try {
      const list = await hostIgnoreList();
      if (!list.includes(r.testId)) {
        toast(`${r.testId} is accepted in the group or global policy. Change it there.`, 'error');
        return;
      }
      const rest = list.filter((id) => id !== r.testId);
      await setLayerKey({ scope: 'host', id: hostId }, ['hardening', 'ignore'], rest.length ? rest : undefined, `Hardening: stop accepting ${r.testId}`);
      toast('This host counts it again.');
    } catch (e) {
      toast(errorText(e), 'error');
    }
  }
</script>

{#if error && !data}
  <div class="banner bad" role="alert"><p>Couldn't load the hardening audit: {error}</p></div>
{:else if !data}
  <div class="skeleton-block"></div>
{:else}
  <div class="stack">
    <section class="card summary">
      <div class="figure">
        <span class="label">Hardening index</span>
        <span class="big {indexTone(data.hardeningIndex)}">{data.hardeningIndex ?? '—'}<span class="of">/ 100</span></span>
        {#if data.hardeningIndex !== null}
          <span class="gauge" role="meter" aria-valuemin="0" aria-valuemax="100" aria-valuenow={data.hardeningIndex} aria-label="Lynis hardening index">
            <span class="fill {indexTone(data.hardeningIndex)}" style:width="{data.hardeningIndex}%"></span>
          </span>
        {/if}
      </div>
      <div class="counts">
        {#if data.auditedAt}
          <span><strong class="n" class:bad-text={warningIds.size > 0}>{warningIds.size}</strong> warning{warningIds.size === 1 ? '' : 's'}</span>
          <span><strong class="n">{suggestionIds.size}</strong> suggestion{suggestionIds.size === 1 ? '' : 's'}</span>
          {#if acceptedCount}<span class="muted">{acceptedCount} accepted</span>{/if}
          {#if data.testsExecuted}<span class="muted">{data.testsExecuted} tests run</span>{/if}
        {/if}
      </div>
      <div class="meta">
        <span class="muted small">
          {#if data.lynisVersion || data.tool.version}Lynis {data.lynisVersion ?? data.tool.version}{/if}
          {#if data.auditedAt} · audited <Time iso={data.auditedAt} />{:else} · not audited yet{/if}
        </span>
        {#if canWrite() && !notInstalled}<button class="btn small" onclick={audit} disabled={auditing}>{auditing ? 'Auditing…' : 'Audit now'}</button>{/if}
      </div>
    </section>

    {#if notInstalled}
      <section class="card pad stack-sm">
        <h2>Lynis isn't installed</h2>
        <p>
          <a href="https://cisofy.com/lynis/" target="_blank" rel="noreferrer">Lynis</a> audits the host's configuration and scores it. It's in every
          supported distribution's repositories (EPEL on the RHEL family), and the agent installs it when <code>agent.autoInstall</code> is on.
          {#if data.tool.reason}<br /><span class="small bad-text">{data.tool.reason}</span>{/if}
        </p>
        <div class="cmd"><code>{installCommand}</code><CopyButton text={installCommand} /></div>
      </section>
    {/if}

    {#if data.lastAuditSucceeded === false}
      <div class="banner bad" role="alert">
        <p><strong>The last audit failed</strong>{#if data.lastAttemptAt} (<Time iso={data.lastAttemptAt} />){/if}: <span class="mono small">{data.lastAuditError}</span>{data.auditedAt ? ' The checklist below is from the last successful audit.' : ''}</p>
      </div>
    {/if}

    {#if data.resolvedSinceLast.length}
      <div class="banner ok">
        <p><strong>Resolved since the previous audit:</strong> {#each data.resolvedSinceLast as id, i (id)}{i ? ', ' : ''}<a class="mono" href={lynisUrl(id)} target="_blank" rel="noreferrer">{id}</a>{/each}</p>
      </div>
    {/if}

    {#if data.auditedAt}
      <section class="card">
        <header>
          <h2>Remediation checklist</h2>
          <span class="hint">{visibleCount} of {rows.length}</span>
        </header>
        <div class="filterbar pad-x">
          <input class="field grow" type="search" placeholder="Test id, category or text…" bind:value={q} aria-label="Search the checklist" />
          {#if acceptedCount}<label class="check"><input type="checkbox" bind:checked={showAccepted} /> Show accepted</label>{/if}
        </div>
        {#if visibleCount === 0}
          <div class="empty">{rows.length ? 'Nothing matches.' : 'Lynis has no warnings or suggestions for this host.'}</div>
        {:else}
          {#each groups as g (g.category)}
            <div class="group">
              <h3>{g.category} <span class="muted">{g.rows.length}</span></h3>
              <ul class="items">
                {#each g.rows as r (r.testId)}
                  {@const note = lynisNotes[r.testId]}
                  <li class:accepted={r.accepted}>
                    <div class="row-head">
                      <a class="mono id" href={lynisUrl(r.testId)} target="_blank" rel="noreferrer" title="What this test checks, on cisofy.com">{r.testId}</a>
                      {#if r.warning}<span class="pill bad">warning</span>{/if}
                      {#if r.accepted}<span class="pill muted">accepted</span>{/if}
                      <span class="spacer"></span>
                      {#if canWrite()}
                        {#if r.accepted}<button class="btn ghost small" onclick={() => unaccept(r)}>Stop accepting</button>
                        {:else}<button class="btn ghost small" onclick={() => accept(r)}>Accept</button>{/if}
                      {/if}
                    </div>
                    {#each r.entries as e, i (i)}
                      <div class="entry">
                        <span>{e.text}</span>
                        {#if e.details}<span class="mono small muted"> · {e.details}</span>{/if}
                        {#if e.solution}<div class="small solution">→ {e.solution}</div>{/if}
                      </div>
                    {/each}
                    {#if note}
                      <div class="note small">
                        {note.text}
                        {#if note.tab}<a href="/hosts/{hostId}?tab={note.tab}">Open {note.tab === 'vulnerabilities' ? 'CVEs' : note.tab[0].toUpperCase() + note.tab.slice(1)} →</a>{/if}
                      </div>
                    {/if}
                  </li>
                {/each}
              </ul>
            </div>
          {/each}
        {/if}
      </section>

      <section class="card pad stack-sm">
        <h2 class="h-sm">Audit settings</h2>
        <p class="muted small">
          Schedule <code>{data.schedule.value}</code>{data.schedule.isDefault ? ' (default)' : ''}. The agent runs
          <code>lynis audit system</code> at low priority with its own profile, which turns off Lynis's upgrade check so the host contacts only this
          server. New warnings and a drop of 5 or more points raise alerts. Lynis only reports; the most important fixes are one click on the
          <a href="/hosts/{hostId}?tab=baseline">Baseline</a> tab.
        </p>
        <p class="small"><a href="/policies/host/{hostId}">Change for this host</a> · <a href="/policies/global">for all hosts</a></p>
      </section>
    {:else if !notInstalled && data.lastAuditSucceeded !== false}
      <div class="empty empty-dashed">
        No audit yet. The agent audits on start and then on <code>{data.schedule.value}</code>; a full audit takes a few minutes.
      </div>
    {/if}
  </div>
{/if}

<style>
  .summary { display: flex; flex-wrap: wrap; align-items: center; gap: 16px 32px; padding: 16px; }
  .figure { display: flex; flex-direction: column; gap: 4px; min-width: 140px; }
  .label { font-size: 12px; color: var(--muted); }
  .figure .big { font-size: 34px; font-weight: 600; line-height: 1; font-variant-numeric: tabular-nums; color: var(--text-strong); }
  .of { font-size: 14px; font-weight: 400; color: var(--muted); margin-left: 4px; }
  .big.ok { color: var(--ok); }
  .big.warn { color: var(--warn); }
  .big.bad { color: var(--bad); }
  .gauge { display: block; width: 140px; height: 6px; border-radius: 3px; background: var(--surface-2); overflow: hidden; }
  .gauge .fill { display: block; height: 100%; border-radius: 3px; background: var(--muted); }
  .gauge .fill.ok { background: var(--ok); }
  .gauge .fill.warn { background: var(--warn); }
  .gauge .fill.bad { background: var(--bad); }
  .counts { display: flex; flex-wrap: wrap; align-items: center; gap: 6px 16px; color: var(--muted); }
  .counts .n { color: var(--text-strong); font-variant-numeric: tabular-nums; }
  .counts .n.bad-text, .bad-text { color: var(--bad); }
  .meta { margin-left: auto; display: flex; flex-wrap: wrap; align-items: center; gap: 10px; }
  .pad { padding: 14px 16px 16px; }
  .pad-x { padding: 0 16px; }
  .stack-sm { display: flex; flex-direction: column; gap: 8px; }
  .stack-sm p, .stack-sm h2 { margin: 0; }
  .h-sm { font-size: 14px; }
  .check { display: inline-flex; align-items: center; gap: 6px; font-size: 13px; color: var(--muted); white-space: nowrap; }
  .group { border-top: 1px solid var(--border); }
  .group h3 { margin: 0; padding: 10px 16px 4px; font-size: 12px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.04em; color: var(--muted); }
  .items { list-style: none; margin: 0; padding: 0 0 6px; }
  .items li { padding: 8px 16px; display: flex; flex-direction: column; gap: 3px; }
  .items li + li { border-top: 1px dashed var(--border); }
  .items li.accepted { opacity: 0.6; }
  .row-head { display: flex; align-items: center; flex-wrap: wrap; gap: 6px; min-height: 26px; }
  .id { font-weight: 600; }
  .spacer { flex: 1; }
  .entry { overflow-wrap: anywhere; }
  .solution { color: var(--muted); margin-top: 1px; }
  .note { margin-top: 2px; padding: 6px 8px; border-radius: 6px; background: var(--surface-2); color: var(--text); }
  .note a { margin-left: 4px; white-space: nowrap; }
  .cmd { display: flex; align-items: flex-start; gap: 8px; }
  .cmd code { flex: 1; min-width: 0; padding: 6px 8px; border-radius: 6px; background: var(--surface-2); font-size: 12px; overflow-wrap: anywhere; white-space: pre-wrap; }
  @media (max-width: 640px) {
    .meta { margin-left: 0; }
  }
</style>
