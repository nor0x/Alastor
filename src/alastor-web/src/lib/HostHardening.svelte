<script lang="ts">
  import { untrack } from 'svelte';
  import { api, errorText, lynisUrl, type Command, type HardeningItem, type HostHardening } from './api';
  import { layerValue, setLayerKey } from './baseline';
  import { indexTone, lynisNotes } from './hardening';
  import { on, refreshOn } from './live.svelte';
  import { canWrite } from './session.svelte';
  import { toast } from './toast.svelte';
  import { confirm } from './ui/confirm.svelte';
  import CopyButton from './ui/CopyButton.svelte';
  import Icon from './ui/Icon.svelte';
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
    // load() reads `data` before its first await; untracked, so a response doesn't re-run this effect.
    untrack(load);
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
      <div class="lead">
        <span class="figure-label">Hardening index</span>
        <span class="figure-value {indexTone(data.hardeningIndex)}">{#if data.hardeningIndex !== null}{data.hardeningIndex}{:else}<span class="nil" aria-label="none"></span>{/if}<span class="figure-of">/ 100</span></span>
        {#if data.hardeningIndex !== null}
          <span class="gauge {indexTone(data.hardeningIndex)}" style:--v={data.hardeningIndex} role="meter" aria-valuemin="0" aria-valuemax="100" aria-valuenow={data.hardeningIndex} aria-label="Lynis hardening index"></span>
        {/if}
      </div>
      <div class="counts">
        {#if data.auditedAt}
          <span class="pair"><strong class="n" class:bad={warningIds.size > 0}>{warningIds.size}</strong> warning{warningIds.size === 1 ? '' : 's'}</span>
          <span class="pair"><strong class="n">{suggestionIds.size}</strong> suggestion{suggestionIds.size === 1 ? '' : 's'}</span>
          {#if acceptedCount}<span class="pair"><strong class="n">{acceptedCount}</strong> accepted</span>{/if}
          {#if data.testsExecuted}<span class="pair"><strong class="n">{data.testsExecuted}</strong> tests run</span>{/if}
        {/if}
      </div>
      <div class="meta">
        <span class="meta-facts">
          {#if data.lynisVersion || data.tool.version}<span>Lynis {data.lynisVersion ?? data.tool.version}</span>{/if}
          {#if data.auditedAt}<span>Audited <Time iso={data.auditedAt} /></span>{:else}<span>Not audited yet</span>{/if}
        </span>
        <span class="keys">{#if canWrite() && !notInstalled}<button class="btn small" onclick={audit} disabled={auditing}>{auditing ? 'Auditing…' : 'Audit now'}</button>{/if}</span>
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
        <Icon name="error" />
        <p><strong>The last audit failed</strong>{#if data.lastAttemptAt} (<Time iso={data.lastAttemptAt} />){/if}: <span class="mono small">{data.lastAuditError}</span>{data.auditedAt ? ' The checklist below is from the last successful audit.' : ''}</p>
      </div>
    {/if}

    {#if data.resolvedSinceLast.length}
      <div class="banner ok">
        <Icon name="check" />
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
              <h3>{g.category} <span class="count">{g.rows.length}</span></h3>
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
                        {#if e.details}<span class="mono small muted details">{e.details}</span>{/if}
                        {#if e.solution}<div class="small solution">{e.solution}</div>{/if}
                      </div>
                    {/each}
                    {#if note}
                      <div class="note small">
                        <span>{note.text}</span>
                        {#if note.tab}<a href="/hosts/{hostId}?tab={note.tab}">Open {note.tab === 'vulnerabilities' ? 'CVEs' : note.tab[0].toUpperCase() + note.tab.slice(1)}</a>{/if}
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
        <p class="small links"><a href="/policies/host/{hostId}">Change for this host</a><a href="/policies/global">for all hosts</a></p>
      </section>
    {:else if !notInstalled && data.lastAuditSucceeded !== false}
      <div class="empty empty-dashed">
        No audit yet. The agent audits on start and then on <code>{data.schedule.value}</code>; a full audit takes a few minutes.
      </div>
    {/if}
  </div>
{/if}

<style>
  /* The summary ledger, the same strip on every host tab: lead figure | counts | when + keys, parted by hairlines. */
  .summary { display: grid; grid-template-columns: minmax(200px, max-content) minmax(0, 1fr) minmax(0, max-content); overflow: hidden; }
  .summary > * { display: flex; flex-direction: column; justify-content: center; gap: var(--space-2xs); min-width: 0; padding: var(--space-md); }
  .summary > * + * { box-shadow: inset 1px 0 0 var(--border); }
  .lead .figure-value { display: inline-flex; align-items: baseline; }
  .lead .figure-value .nil { width: 24px; height: 2px; align-self: center; }
  .counts { flex-direction: row; flex-wrap: wrap; align-items: center; align-content: center; justify-content: flex-start; gap: var(--space-xs) var(--space-lg); color: var(--muted); }
  .pair { display: inline-flex; align-items: baseline; gap: var(--space-2xs); color: var(--muted); }
  .pair .n { font-family: var(--font-display); font-weight: 600; font-size: var(--text-lg); line-height: 1; color: var(--text-strong); font-variant-numeric: tabular-nums; }
  .pair .n.bad { color: var(--bad); }
  .meta { align-items: flex-end; text-align: right; }
  .meta-facts { display: flex; flex-direction: column; align-items: inherit; gap: var(--space-3xs); font-size: var(--text-sm); color: var(--muted); }
  .keys { display: flex; flex-wrap: wrap; justify-content: flex-end; gap: var(--space-xs); margin-top: var(--space-2xs); }
  .keys:empty { display: none; }
  @media (max-width: 760px) {
    .summary { grid-template-columns: minmax(0, 1fr); }
    .summary > * + * { box-shadow: inset 0 1px 0 var(--border); }
    .counts:empty { display: none; }
    .meta { align-items: flex-start; text-align: left; }
    .keys { justify-content: flex-start; }
  }
  .lead .gauge { margin-top: var(--space-xs); }

  .pad { padding: var(--space-md); }
  .pad-x { padding: 0 var(--space-md); }
  .stack-sm { display: flex; flex-direction: column; gap: var(--space-xs); }
  .stack-sm p, .stack-sm h2 { margin: 0; }
  .stack-sm h2 { font-size: var(--text-section); text-wrap: balance; }
  .stack-sm h2.h-sm { font-size: var(--text-md); }
  .links { display: flex; flex-wrap: wrap; gap: var(--space-xs) var(--space-sm); }
  .links a + a { padding-left: var(--space-sm); box-shadow: inset 1px 0 0 var(--border); }
  .bad-text { color: var(--bad); }
  .filterbar { margin: var(--space-sm) 0; }
  .check { display: inline-flex; align-items: center; gap: var(--space-xs); font-size: var(--text-sm); color: var(--muted); white-space: nowrap; }

  /* Checklist: a group head per category, hairline rows under it. */
  .group { border-top: var(--rule-hair) solid var(--border); }
  .group h3 { display: flex; align-items: baseline; gap: var(--space-xs); margin: 0; padding: var(--space-sm) var(--space-md) var(--space-2xs); font-family: var(--font-display); font-weight: 500; font-size: var(--text-sm); color: var(--muted); }
  .group h3 .count { font-variant-numeric: tabular-nums; }
  .items { list-style: none; margin: 0; padding: 0 0 var(--space-xs); }
  .items li { display: flex; flex-direction: column; gap: var(--space-2xs); padding: var(--space-xs) var(--space-md); }
  .items li + li { border-top: var(--rule-hair) solid var(--border); }
  .items li.accepted { color: var(--muted); }
  .items li.accepted .id { color: var(--color-ink-2); }
  .row-head { display: flex; align-items: center; flex-wrap: wrap; gap: var(--space-xs); min-height: 28px; }
  .id { font-weight: 500; }
  .spacer { flex: 1; }
  .entry { overflow-wrap: anywhere; }
  .details { margin-left: var(--space-xs); }
  .solution { margin-top: var(--space-3xs); padding-left: var(--space-sm); color: var(--muted); }
  /* A note is a paper-2 well inside the panel. */
  .note { display: flex; flex-wrap: wrap; align-items: baseline; gap: var(--space-2xs) var(--space-sm); margin-top: var(--space-2xs); padding: var(--space-xs) var(--space-sm); border-radius: var(--radius-input); background: var(--color-paper-2); color: var(--text); }
  .note a { white-space: nowrap; font-family: var(--font-display); font-weight: 500; }
</style>
