<script lang="ts">
  import { untrack } from 'svelte';
  import { isMap, isScalar, parseDocument, type Document } from 'yaml';
  import { api, ApiError, errorText, type PolicyIssue, type PolicyLayerDetail, type PolicyPreview, type PolicyVersion } from '../lib/api';
  import { fleet } from '../lib/fleet.svelte';
  import { on } from '../lib/live.svelte';
  import { setLeaveGuard } from '../lib/router.svelte';
  import { canWrite } from '../lib/session.svelte';
  import { toast } from '../lib/toast.svelte';
  import { fullDate } from '../lib/format';
  import { fieldSections, type PolicyField } from '../lib/policyFields';
  import { confirm } from '../lib/ui/confirm.svelte';
  import Icon from '../lib/ui/Icon.svelte';
  import Modal from '../lib/ui/Modal.svelte';
  import Time from '../lib/ui/Time.svelte';

  let { scope, targetId = null }: { scope: 'global' | 'group' | 'host'; targetId?: string | null } = $props();

  const scopeEnum = $derived(scope === 'global' ? 'Global' : scope === 'group' ? 'Group' : 'Host');
  const endpoint = $derived(scope === 'global' ? '/api/policies/global' : `/api/policies/${scope}/${targetId}`);
  const targetName = $derived(
    scope === 'global' ? 'All hosts'
      : scope === 'group' ? (fleet.groups.find((g) => g.id === targetId)?.name ?? 'group')
      : (fleet.hosts.find((h) => h.id === targetId)?.name ?? 'host'),
  );

  let detail = $state<PolicyLayerDetail | null>(null);
  let text = $state('');
  let saved = $state('');
  let loadError = $state('');
  let mode = $state<'form' | 'yaml'>('form');
  let side = $state<'check' | 'fail2ban' | 'effective'>('check');
  let preview = $state<PolicyPreview | null>(null);
  let previewing = $state(false);
  let saveIssues = $state<PolicyIssue[]>([]);
  let comment = $state('');
  let saving = $state(false);
  let remoteChanged = $state(false);

  const dirty = $derived(text !== saved);
  const issues = $derived(saveIssues.length ? saveIssues : (preview?.issues ?? []));
  const errors = $derived(issues.filter((i) => i.level === 'Error'));
  const readOnly = $derived(!canWrite());

  function template(): string {
    const what = scope === 'group' ? `group "${targetName}"` : `host "${targetName}"`;
    return `# Overrides for ${what}. List only the keys you want to change;\n# everything else is inherited from ${scope === 'host' ? 'its group and ' : ''}the global policy.\n#\n# banning:\n#   defaults:\n#     maxretry: 3\n#   jails:\n#     nginx-http-auth:\n#       enabled: true\n`;
  }

  async function load() {
    try {
      const d = await api<PolicyLayerDetail>(endpoint);
      detail = d;
      const yaml = d.layer ? d.yaml : template();
      text = yaml;
      saved = d.layer ? yaml : yaml; // an untouched template is not "dirty"
      saveIssues = [];
      remoteChanged = false;
      loadError = '';
    } catch (e) {
      loadError = errorText(e);
    }
  }

  $effect(() => {
    void endpoint;
    untrack(load);
  });

  // Someone else saved: offer to reload instead of silently replacing the editor's content.
  $effect(() => on('policyChanged', async () => {
    const d = await api<PolicyLayerDetail>(endpoint).catch(() => null);
    if (!d || !detail) return;
    if ((d.layer?.currentVersion ?? 0) === (detail.layer?.currentVersion ?? 0)) return;
    if (!dirty) load();
    else remoteChanged = true;
  }));

  // Live validation and preview, debounced.
  $effect(() => {
    const yaml = text;
    const s = scopeEnum;
    const id = targetId;
    previewing = true;
    const t = setTimeout(async () => {
      try {
        preview = await api<PolicyPreview>('/api/policies/preview', { method: 'POST', body: JSON.stringify({ scope: s, targetId: id, yaml }) });
        saveIssues = [];
      } catch {
        /* keep the last preview */
      } finally {
        previewing = false;
      }
    }, 450);
    return () => clearTimeout(t);
  });

  $effect(() => {
    if (!dirty) return;
    const handler = (e: BeforeUnloadEvent) => e.preventDefault();
    window.addEventListener('beforeunload', handler);
    const off = setLeaveGuard(() => window.confirm('You have unsaved policy changes. Leave without saving?'));
    return () => {
      window.removeEventListener('beforeunload', handler);
      off();
    };
  });

  async function save() {
    if (readOnly || saving) return;
    saving = true;
    try {
      const v = await api<PolicyVersion>(endpoint, { method: 'PUT', body: JSON.stringify({ yaml: text, comment: comment.trim() || null }) });
      toast(`Saved as v${v.version}. Online agents apply it within seconds.`);
      comment = '';
      await load();
    } catch (e) {
      if (e instanceof ApiError && e.status === 422) {
        saveIssues = ((e.body as { issues?: PolicyIssue[] })?.issues) ?? [];
        side = 'check';
        toast('Not saved: the policy has errors.', 'error');
      } else {
        toast(errorText(e), 'error');
      }
    } finally {
      saving = false;
    }
  }

  function onKey(e: KeyboardEvent) {
    if ((e.ctrlKey || e.metaKey) && e.key === 's') {
      e.preventDefault();
      if (dirty && !errors.length) save();
    }
  }

  // ---- Versions ----
  let viewOpen = $state(false);
  let viewing = $state<{ version: number; yaml: string; comment: string | null; createdAt: string; createdBy: string } | null>(null);

  async function view(v: PolicyVersion) {
    if (!detail?.layer) return;
    viewing = await api(`/api/policies/layers/${detail.layer.id}/versions/${v.version}`);
    viewOpen = true;
  }

  async function revert(version: number) {
    if (!detail?.layer) return;
    const ok = await confirm(`Revert to v${version}?`, `Creates a new version with the content of v${version} and rolls it out. History is kept, so this can be undone the same way.`, { confirmLabel: `Revert to v${version}` });
    if (!ok) return;
    try {
      const v = await api<PolicyVersion>(`/api/policies/layers/${detail.layer.id}/revert/${version}`, { method: 'POST' });
      viewOpen = false;
      toast(`Reverted: v${v.version} has the content of v${version}.`);
      await load();
    } catch (e) {
      toast(errorText(e), 'error');
    }
  }

  // ---- Form view: edits single keys in the YAML document, keeping comments and layout ----
  const doc = $derived.by<Document | null>(() => {
    const d = parseDocument(text);
    return d.errors.length ? null : d;
  });
  const effectiveDoc = $derived(preview?.effectiveYaml ? parseDocument(preview.effectiveYaml) : null);

  function layerValue(f: PolicyField): string {
    const v = doc?.getIn(f.path);
    return v === undefined || v === null ? '' : String(v);
  }

  function inherited(f: PolicyField): string {
    const v = effectiveDoc?.getIn(f.path);
    return v === undefined || v === null ? (f.placeholderDefault ?? '') : String(v);
  }

  function setField(f: PolicyField, raw: string) {
    const d = parseDocument(text);
    if (d.errors.length) return;
    const value = raw.trim();
    if (!value) {
      d.deleteIn(f.path);
      // Drop parents that became empty, so clearing a field doesn't leave "agent: {}" behind.
      for (let i = f.path.length - 1; i > 0; i--) {
        const parent = d.getIn(f.path.slice(0, i));
        if (isMap(parent) && parent.items.length === 0) d.deleteIn(f.path.slice(0, i));
        else break;
      }
    } else {
      const node = d.createNode(f.kind === 'int' && /^\d+$/.test(value) ? Number(value) : value);
      // Quote words YAML 1.1 parsers read as booleans ("off" is a valid schedule).
      if (isScalar(node) && typeof node.value === 'string' && /^(off|on|yes|no|true|false|y|n)$/i.test(node.value)) node.type = 'QUOTE_DOUBLE';
      if (d.contents === null || !isMap(d.contents)) d.contents = d.createNode({}) as unknown as typeof d.contents;
      d.setIn(f.path, node);
    }
    text = d.toString();
  }

  function fieldIssue(f: PolicyField): PolicyIssue | undefined {
    const path = f.path.join('.').toLowerCase();
    return issues.find((i) => i.path.toLowerCase() === path);
  }

  // ---- YAML view: line numbers + issue markers ----
  let textarea = $state<HTMLTextAreaElement>();
  let gutter = $state<HTMLDivElement>();
  const lineCount = $derived(text.split('\n').length);
  const issueLines = $derived(new Set(issues.filter((i) => i.line).map((i) => i.line!)));

  function goToLine(line: number) {
    mode = 'yaml';
    requestAnimationFrame(() => {
      if (!textarea) return;
      const lines = text.split('\n');
      const start = lines.slice(0, line - 1).reduce((n, l) => n + l.length + 1, 0);
      textarea.focus();
      textarea.setSelectionRange(start, start + (lines[line - 1]?.length ?? 0));
      textarea.scrollTop = Math.max(0, (line - 5) * 19.5);
    });
  }

  function onTab(e: KeyboardEvent) {
    if (e.key !== 'Tab' || e.shiftKey || !textarea) return;
    e.preventDefault();
    const { selectionStart: s, selectionEnd: end } = textarea;
    text = text.slice(0, s) + '  ' + text.slice(end);
    requestAnimationFrame(() => textarea?.setSelectionRange(s + 2, s + 2));
  }

  function nextRun(iso: string) {
    // Host-local wall-clock time without an offset: show it as written.
    return new Date(iso).toLocaleString(undefined, { weekday: 'short', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
  }
  const scheduleLabels: Record<string, string> = Object.fromEntries(fieldSections.flatMap((s) => s.fields).map((f) => [f.path.join('.'), f.label]));
</script>

<svelte:window onkeydown={onKey} />

<div class="crumbs"><a href="/policies">Policies</a> /</div>
<div class="page-head">
  <div>
    <h1>{scope === 'global' ? 'Global policy' : `${scope === 'group' ? 'Group' : 'Host'} overrides: ${targetName}`}</h1>
    <p class="sub byline">
      {#if detail?.layer}<span class="ver mono">v{detail.layer.currentVersion}</span><span>saved by {detail.layer.updatedBy} <Time iso={detail.layer.updatedAt} /></span>
      {:else if detail}<span>No overrides yet. Saving creates v1.</span>{/if}
      {#if scope === 'host' && targetId}<span class="sep"><a href="/hosts/{targetId}?tab=policy">host's effective policy</a></span>{/if}
    </p>
  </div>
  {#if !readOnly}
    <div class="actions">
      <input class="field comment" placeholder="Change note (optional)" bind:value={comment} maxlength="200" aria-label="Change note" />
      <button class="btn" disabled={!dirty} onclick={() => { text = saved; saveIssues = []; }}>Discard</button>
      <button class="btn primary" disabled={!dirty || saving || errors.length > 0} onclick={save} title="Ctrl+S">
        {saving ? 'Saving…' : errors.length ? `${errors.length} error${errors.length > 1 ? 's' : ''}` : 'Save & roll out'}
      </button>
    </div>
  {/if}
</div>

{#if loadError}<div class="banner bad spaced" role="alert"><Icon name="error" /><p>{loadError}</p></div>{/if}
{#if remoteChanged}
  <div class="banner warn spaced split"><Icon name="alert" /><p>Someone else saved a new version while you were editing.</p><button class="btn small" onclick={load}>Load theirs (discard mine)</button></div>
{/if}
{#if readOnly}<div class="banner info spaced"><Icon name="info" /><p>Read-only access: you can view and validate, but not save.</p></div>{/if}

{#if detail}
  <div class="editor-layout">
    <section class="card editor">
      <nav class="tabs inner" aria-label="Editor mode">
        <button class:on={mode === 'form'} onclick={() => (mode = 'form')}>Form</button>
        <button class:on={mode === 'yaml'} onclick={() => (mode = 'yaml')}>YAML {#if dirty}<span class="count">edited</span>{/if}</button>
      </nav>

      {#if mode === 'form'}
        {#if !doc}
          <div class="banner bad m"><Icon name="error" /><p>The YAML has a syntax error, so the form is unavailable. Fix it in the YAML view.</p></div>
        {:else}
          <div class="form-view">
            <p class="muted small intro">
              {scope === 'global' ? 'Empty fields use the built-in default (shown greyed out).' : 'Empty fields inherit the value shown greyed out. Type to override it for this ' + scope + '.'}
              Jails, the allowlist and other keys are edited in the YAML view.
            </p>
            {#each fieldSections as section (section.title)}
              <fieldset>
                <legend>{section.title}</legend>
                <p class="muted small desc">{section.description}</p>
                <div class="fields">
                  {#each section.fields as f (f.path.join('.'))}
                    {@const issue = fieldIssue(f)}
                    {@const own = layerValue(f)}
                    <label class="f" class:overridden={own !== '' && scope !== 'global'}>
                      <span class="name">{f.label}{#if own !== '' && scope !== 'global'}<span class="ovr">override</span>{/if}</span>
                      <input
                        class="field mono" class:invalid={!!issue}
                        value={own}
                        placeholder={inherited(f)}
                        disabled={readOnly}
                        onchange={(e) => setField(f, e.currentTarget.value)}
                        aria-describedby="help-{f.path.join('-')}"
                      />
                      <span class="help" id="help-{f.path.join('-')}">{#if issue}<span class="err">{issue.message}</span>{:else}{f.help}{/if}</span>
                    </label>
                  {/each}
                </div>
              </fieldset>
            {/each}
          </div>
        {/if}
      {:else}
        <div class="code">
          <div class="gutter" bind:this={gutter} aria-hidden="true">
            {#each Array(lineCount) as _, i (i)}<div class:bad={issueLines.has(i + 1)}>{i + 1}</div>{/each}
          </div>
          <textarea
            bind:this={textarea}
            bind:value={text}
            spellcheck="false"
            readonly={readOnly}
            aria-label="Policy YAML"
            onscroll={() => gutter && textarea && (gutter.scrollTop = textarea.scrollTop)}
            onkeydown={onTab}
          ></textarea>
        </div>
      {/if}
    </section>

    <aside class="card preview">
      <nav class="tabs inner" aria-label="Preview">
        <button class:on={side === 'check'} onclick={() => (side = 'check')}>Check{#if errors.length}<span class="count bad">{errors.length}</span>{/if}</button>
        <button class:on={side === 'fail2ban'} onclick={() => (side = 'fail2ban')}>fail2ban config</button>
        <button class:on={side === 'effective'} onclick={() => (side = 'effective')}>Effective</button>
      </nav>
      <div class="side-body" class:dim={previewing}>
        {#if side === 'check'}
          {#if issues.length}
            <ul class="issues">
              {#each issues as i, n (n)}
                <li class={i.level === 'Error' ? 'bad' : 'warn'}>
                  <span class="lvl"><Icon name={i.level === 'Error' ? 'error' : 'alert'} label={i.level} /></span>
                  <div class="issue">
                    <div>{i.message}</div>
                    <div class="where muted small">
                      <span class="mono">{i.path || '(document)'}</span>
                      {#if i.line}<button class="link" onclick={() => goToLine(i.line!)}>line {i.line}</button>{/if}
                    </div>
                  </div>
                </li>
              {/each}
            </ul>
          {:else if preview}
            <p class="ok-line"><Icon name="check" /><span>Valid.</span> {#if preview.revision}<span class="muted small">Effective revision <span class="mono">{preview.revision}</span></span>{/if}</p>
          {/if}

          {#if preview?.schedules?.length}
            <h3>Schedules</h3>
            <p class="muted small sched-note">Next runs in host-local time, before the per-host spread.</p>
            <table class="table sched">
              <tbody>
                {#each preview.schedules as s (s.path)}
                  <tr>
                    <td>
                      <div>{scheduleLabels[s.path] ?? s.path}</div>
                      <div class="expr small muted"><span class="mono">{s.schedule}</span>{#if s.isDefault}<span>default</span>{/if}</div>
                    </td>
                    <td class="small runs">
                      {#if s.kind === 'off'}<span class="pill muted">off</span>
                      {:else}{#each s.nextRunsHostLocal as r (r)}<div class="nowrap">{nextRun(r)}</div>{/each}{/if}
                    </td>
                  </tr>
                {/each}
              </tbody>
            </table>
          {/if}
        {:else if side === 'fail2ban'}
          <p class="muted small lead">What the agent writes to <code>/etc/fail2ban/jail.d/alastor.local</code>{scope === 'global' ? ' on a host with no group or host overrides' : ''}.</p>
          {#if preview?.fail2BanConfig}<pre class="code-block">{preview.fail2BanConfig}</pre>{:else}<p class="muted">Fix the errors to see the rendered config.</p>{/if}
        {:else}
          <p class="muted small lead">The merged result {scope === 'global' ? 'for a host with no overrides' : `for this ${scope}`}, including the allowlist from the Bans page.</p>
          {#if preview?.effectiveYaml}<pre class="code-block">{preview.effectiveYaml}</pre>{:else}<p class="muted">Fix the errors to see the effective policy.</p>{/if}
        {/if}
      </div>
    </aside>
  </div>

  {#if detail.versions.length}
    <section class="card versions">
      <header><h2>History</h2><span class="hint">every save is a new immutable version</span></header>
      <div class="table-wrap">
        <table class="table">
          <thead><tr><th>Version</th><th>Note</th><th class="hide-sm">By</th><th>When</th><th></th></tr></thead>
          <tbody>
            {#each detail.versions as v (v.version)}
              <tr>
                <td class="nowrap"><span class="mono">v{v.version}</span> {#if v.version === detail.layer?.currentVersion}<span class="pill ok">current</span>{/if}</td>
                <td class="small">{v.comment ?? ''}</td>
                <td class="hide-sm">{v.createdBy}</td>
                <td class="nowrap" title={fullDate(v.createdAt)}><Time iso={v.createdAt} /></td>
                <td class="actions">
                  <button class="btn small" onclick={() => view(v)}>View</button>
                  {#if !readOnly && v.version !== detail.layer?.currentVersion}<button class="btn small" onclick={() => revert(v.version)}>Revert to this</button>{/if}
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    </section>
  {/if}
{:else if !loadError}
  <div class="skeleton-block" style="height:400px"></div>
{/if}

<Modal bind:open={viewOpen} title={viewing ? `v${viewing.version}` : 'Version'} wide>
  {#if viewing}
    <p class="muted small byline modal-meta"><span>{viewing.createdBy}</span><span class="sep">{fullDate(viewing.createdAt)}</span>{#if viewing.comment}<span class="sep">{viewing.comment}</span>{/if}</p>
    <pre class="code-block">{viewing.yaml || '(empty)'}</pre>
  {/if}
  {#snippet footer()}
    {#if viewing && !readOnly}
      <button class="btn" onclick={() => { if (viewing) { text = viewing.yaml; mode = 'yaml'; viewOpen = false; } }}>Copy into editor</button>
      {#if viewing.version !== detail?.layer?.currentVersion}<button class="btn primary" onclick={() => viewing && revert(viewing.version)}>Revert to v{viewing.version}</button>{/if}
    {/if}
  {/snippet}
</Modal>

<style>
  .byline { display: flex; flex-wrap: wrap; align-items: center; gap: var(--space-2xs) var(--space-sm); }
  .byline .sep { padding-left: var(--space-sm); border-left: var(--rule-hair) solid var(--border-strong); }
  .ver { padding: 0 var(--space-2xs); border-radius: 4px; background: var(--color-paper-3); color: var(--color-ink); line-height: 20px; }
  .comment { width: 220px; }
  .spaced { margin-bottom: var(--space-sm); align-items: center; }
  .banner > :global(.icon) { margin-top: var(--space-3xs); }
  .split p { flex: 1; }
  .editor-layout { display: grid; grid-template-columns: minmax(0, 1.4fr) minmax(0, 1fr); gap: var(--space-md); align-items: start; }
  .tabs.inner { margin: 0; padding: 0 var(--space-xs); }
  .count.bad { background: var(--bad-bg); color: var(--bad); }
  .m { margin: var(--space-md); }

  /* Form view */
  .form-view { display: flex; flex-direction: column; gap: var(--space-lg); padding: var(--space-md); }
  .intro { margin: 0; max-width: 75ch; }
  fieldset { border: 0; margin: 0; padding: var(--space-md) 0 0; border-top: var(--rule-hair) solid var(--border); }
  legend { float: left; width: 100%; padding: 0; font-family: var(--font-display); font-weight: 600; font-size: var(--text-lg); color: var(--text-strong); }
  .desc { clear: both; margin: 0 0 var(--space-sm); padding-top: var(--space-3xs); }
  .fields { display: grid; grid-template-columns: repeat(auto-fill, minmax(min(100%, 230px), 1fr)); gap: var(--space-md); }
  .f { display: flex; flex-direction: column; gap: var(--space-2xs); }
  .f .name { display: flex; align-items: center; gap: var(--space-xs); font-family: var(--font-display); font-weight: 500; font-size: var(--text-sm); color: var(--color-ink-2); }
  .ovr { font-size: var(--text-xs); font-weight: 500; color: var(--color-accent-deep); padding: 0 var(--space-2xs); border-radius: 4px; background: var(--color-accent-wash); line-height: 18px; }
  .f input::placeholder { color: color-mix(in oklab, var(--muted) 70%, transparent); }
  .f.overridden input { border-color: var(--color-accent); }
  .f input.invalid { border-color: var(--bad); }
  .f .help { font-size: var(--text-xs); color: var(--muted); line-height: 1.4; }
  .err { color: var(--bad); }

  /* YAML view: a graphite pane. Line height is fixed at 19.5px, goToLine() scrolls by it. */
  .code { display: flex; height: 560px; background: var(--color-graphite); font-family: var(--mono); font-size: 13px; line-height: 19.5px; font-variant-ligatures: none; border-radius: 0 0 var(--radius-card) var(--radius-card); overflow: hidden; }
  .gutter { flex: none; width: 48px; padding: var(--space-xs) 0; overflow: hidden; text-align: right; color: var(--color-graphite-muted); background: var(--color-graphite-2); user-select: none; font-variant-numeric: tabular-nums; }
  .gutter div { padding-right: var(--space-xs); }
  .gutter div.bad { color: var(--color-graphite-error); background: color-mix(in oklab, var(--color-graphite-error) 22%, transparent); }
  textarea {
    flex: 1; min-width: 0; padding: var(--space-xs) var(--space-sm); border: 0; resize: none; outline: none;
    background: var(--color-graphite); color: var(--color-graphite-ink); caret-color: var(--color-accent-2);
    font: inherit; line-height: inherit; white-space: pre; tab-size: 2;
  }
  textarea::selection { background: color-mix(in oklab, var(--color-accent-2) 35%, transparent); color: var(--color-graphite-ink); }
  textarea:focus-visible { box-shadow: inset 0 0 0 2px var(--color-accent-2); }

  /* Preview side: paper */
  .side-body { padding: var(--space-md); max-height: 620px; overflow: auto; transition: opacity var(--dur-short) var(--ease-out); }
  .side-body.dim { opacity: 0.7; }
  .lead { margin: 0 0 var(--space-sm); }
  .issues { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; border-top: var(--rule-hair) solid var(--border); }
  .issues li { display: flex; gap: var(--space-xs); padding: var(--space-xs) 0; border-bottom: var(--rule-hair) solid var(--border); }
  .issue { min-width: 0; overflow-wrap: anywhere; }
  .issues .lvl { flex: none; display: inline-flex; padding-top: var(--space-3xs); }
  .issues li.bad .lvl { color: var(--bad); }
  .issues li.warn .lvl { color: var(--warn); }
  .where { display: flex; flex-wrap: wrap; gap: var(--space-sm); margin-top: var(--space-3xs); }
  .link { border: 0; background: none; color: var(--link); cursor: pointer; padding: 0; font: inherit; }
  .link:hover { text-decoration: underline; text-decoration-color: var(--color-accent); }
  .ok-line { display: flex; flex-wrap: wrap; align-items: center; gap: var(--space-2xs) var(--space-xs); margin: 0 0 var(--space-xs); color: var(--ok); }
  h3 { margin: var(--space-lg) 0 var(--space-3xs); font-size: var(--text-md); }
  .sched-note { margin: 0 0 var(--space-xs); }
  .sched td { padding: var(--space-xs) var(--space-xs) var(--space-xs) 0; height: auto; vertical-align: top; }
  .sched td:first-child { padding-left: 0; }
  .sched td:last-child { padding-right: 0; }
  .runs { font-variant-numeric: tabular-nums; color: var(--color-ink-2); }
  .expr { display: flex; gap: var(--space-xs); }
  .expr > span + span { padding-left: var(--space-xs); border-left: var(--rule-hair) solid var(--border-strong); }
  .versions { margin-top: var(--space-md); }
  .modal-meta { margin: 0 0 var(--space-sm); }

  @media (max-width: 1000px) {
    .editor-layout { grid-template-columns: 1fr; }
    .code { height: 420px; }
  }
  @media (max-width: 640px) {
    .comment { width: 100%; flex: 1 1 100%; }
  }
</style>
