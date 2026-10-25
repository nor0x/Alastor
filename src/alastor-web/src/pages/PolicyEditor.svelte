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
    <p class="sub">
      {#if detail?.layer}v{detail.layer.currentVersion} · saved by {detail.layer.updatedBy} <Time iso={detail.layer.updatedAt} />
      {:else if detail}No overrides yet. Saving creates v1.{/if}
      {#if scope === 'host' && targetId} · <a href="/hosts/{targetId}?tab=policy">host's effective policy</a>{/if}
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

{#if loadError}<div class="banner bad" role="alert"><p>{loadError}</p></div>{/if}
{#if remoteChanged}
  <div class="banner warn spaced"><p>Someone else saved a new version while you were editing.</p><button class="btn small" onclick={load}>Load theirs (discard mine)</button></div>
{/if}
{#if readOnly}<div class="banner info spaced"><p>Read-only access: you can view and validate, but not save.</p></div>{/if}

{#if detail}
  <div class="editor-layout">
    <section class="card editor">
      <nav class="tabs inner" aria-label="Editor mode">
        <button class:on={mode === 'form'} onclick={() => (mode = 'form')}>Form</button>
        <button class:on={mode === 'yaml'} onclick={() => (mode = 'yaml')}>YAML {#if dirty}<span class="count">edited</span>{/if}</button>
      </nav>

      {#if mode === 'form'}
        {#if !doc}
          <div class="banner bad m"><p>The YAML has a syntax error, so the form is unavailable. Fix it in the YAML view.</p></div>
        {:else}
          <div class="form-view">
            <p class="muted small intro">
              {scope === 'global' ? 'Empty fields use the built-in default (shown greyed out).' : 'Empty fields inherit the value shown greyed out. Type to override it for this ' + scope + '.'}
              Jails, the allowlist and other keys are edited in the YAML view.
            </p>
            {#each fieldSections as section (section.title)}
              <fieldset>
                <legend>{section.title}</legend>
                <p class="muted small">{section.description}</p>
                <div class="fields">
                  {#each section.fields as f (f.path.join('.'))}
                    {@const issue = fieldIssue(f)}
                    {@const own = layerValue(f)}
                    <label class="f" class:overridden={own !== '' && scope !== 'global'}>
                      <span class="name">{f.label}{#if own !== '' && scope !== 'global'}<span class="pill info tiny">override</span>{/if}</span>
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
                  <span class="lvl">{i.level === 'Error' ? '✕' : '⚠'}</span>
                  <div>
                    <div>{i.message}</div>
                    <div class="muted small">
                      <span class="mono">{i.path || '(document)'}</span>
                      {#if i.line}· <button class="link" onclick={() => goToLine(i.line!)}>line {i.line}</button>{/if}
                    </div>
                  </div>
                </li>
              {/each}
            </ul>
          {:else if preview}
            <p class="ok-line">✓ Valid. {#if preview.revision}<span class="muted small">Effective revision <span class="mono">{preview.revision}</span></span>{/if}</p>
          {/if}

          {#if preview?.schedules?.length}
            <h3>Schedules</h3>
            <p class="muted small">Next runs in host-local time, before the per-host spread.</p>
            <table class="table sched">
              <tbody>
                {#each preview.schedules as s (s.path)}
                  <tr>
                    <td>
                      <div>{scheduleLabels[s.path] ?? s.path}</div>
                      <div class="mono small muted">{s.schedule}{s.isDefault ? ' · default' : ''}</div>
                    </td>
                    <td class="small">
                      {#if s.kind === 'off'}<span class="pill muted">off</span>
                      {:else}{#each s.nextRunsHostLocal as r (r)}<div class="nowrap">{nextRun(r)}</div>{/each}{/if}
                    </td>
                  </tr>
                {/each}
              </tbody>
            </table>
          {/if}
        {:else if side === 'fail2ban'}
          <p class="muted small">What the agent writes to <code>/etc/fail2ban/jail.d/alastor.local</code>{scope === 'global' ? ' on a host with no group or host overrides' : ''}.</p>
          {#if preview?.fail2BanConfig}<pre class="out">{preview.fail2BanConfig}</pre>{:else}<p class="muted">Fix the errors to see the rendered config.</p>{/if}
        {:else}
          <p class="muted small">The merged result {scope === 'global' ? 'for a host with no overrides' : `for this ${scope}`}, including the allowlist from the Bans page.</p>
          {#if preview?.effectiveYaml}<pre class="out">{preview.effectiveYaml}</pre>{:else}<p class="muted">Fix the errors to see the effective policy.</p>{/if}
        {/if}
      </div>
    </aside>
  </div>

  {#if detail.versions.length}
    <section class="card versions">
      <header><h2>History</h2><span class="hint">every save is a new immutable version</span></header>
      <table class="table">
        <thead><tr><th>Version</th><th>Note</th><th class="hide-sm">By</th><th>When</th><th></th></tr></thead>
        <tbody>
          {#each detail.versions as v (v.version)}
            <tr>
              <td>v{v.version} {#if v.version === detail.layer?.currentVersion}<span class="pill ok">current</span>{/if}</td>
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
    </section>
  {/if}
{:else if !loadError}
  <div class="skeleton-block" style="height:400px"></div>
{/if}

<Modal bind:open={viewOpen} title={viewing ? `v${viewing.version}` : 'Version'} wide>
  {#if viewing}
    <p class="muted small">{viewing.createdBy} · {fullDate(viewing.createdAt)}{viewing.comment ? ` · ${viewing.comment}` : ''}</p>
    <pre class="out">{viewing.yaml || '(empty)'}</pre>
  {/if}
  {#snippet footer()}
    {#if viewing && !readOnly}
      <button class="btn" onclick={() => { if (viewing) { text = viewing.yaml; mode = 'yaml'; viewOpen = false; } }}>Copy into editor</button>
      {#if viewing.version !== detail?.layer?.currentVersion}<button class="btn primary" onclick={() => viewing && revert(viewing.version)}>Revert to v{viewing.version}</button>{/if}
    {/if}
  {/snippet}
</Modal>

<style>
  .comment { width: 220px; }
  .spaced { margin-bottom: 12px; justify-content: space-between; align-items: center; }
  .editor-layout { display: grid; grid-template-columns: minmax(0, 1.4fr) minmax(0, 1fr); gap: 16px; align-items: start; }
  .tabs.inner { margin: 0; padding: 0 8px; }
  .count.bad { background: var(--bad-bg); color: var(--bad); }
  .m { margin: 16px; }

  .form-view { padding: 16px; display: flex; flex-direction: column; gap: 20px; }
  .intro { margin: 0; }
  fieldset { border: 0; margin: 0; padding: 0; }
  legend { font-weight: 600; color: var(--text-strong); padding: 0; }
  fieldset > p { margin: 2px 0 10px; }
  .fields { display: grid; grid-template-columns: repeat(auto-fill, minmax(230px, 1fr)); gap: 14px 16px; }
  .f { display: flex; flex-direction: column; gap: 4px; }
  .f .name { display: flex; align-items: center; gap: 6px; font-size: 13px; color: var(--text); }
  .f input::placeholder { color: color-mix(in srgb, var(--muted) 70%, transparent); }
  .f.overridden input { border-color: color-mix(in srgb, var(--info) 60%, transparent); }
  .f input.invalid { border-color: var(--bad); }
  .f .help { font-size: 11.5px; color: var(--muted); line-height: 1.4; }
  .err { color: var(--bad); }
  .tiny { font-size: 10px; line-height: 16px; padding: 0 6px; }

  .code { display: flex; height: 560px; font-family: var(--mono); font-size: 13px; line-height: 19.5px; }
  .gutter { flex: none; width: 44px; padding: 10px 0; overflow: hidden; text-align: right; color: var(--muted); background: var(--surface-2); border-right: 1px solid var(--border); user-select: none; }
  .gutter div { padding-right: 8px; opacity: 0.6; }
  .gutter div.bad { opacity: 1; color: var(--bad); background: var(--bad-bg); }
  textarea { flex: 1; padding: 10px 12px; border: 0; background: var(--bg); resize: none; outline: none; font: inherit; line-height: inherit; white-space: pre; tab-size: 2; }

  .side-body { padding: 14px 16px; max-height: 620px; overflow: auto; transition: opacity 0.15s; }
  .side-body.dim { opacity: 0.7; }
  .issues { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 8px; }
  .issues li { display: flex; gap: 8px; padding: 8px 10px; border-radius: 6px; }
  .issues li.bad { background: var(--bad-bg); }
  .issues li.warn { background: var(--warn-bg); }
  .issues .lvl { flex: none; font-weight: 700; }
  .issues li.bad .lvl { color: var(--bad); }
  .issues li.warn .lvl { color: var(--warn); }
  .link { border: 0; background: none; color: var(--link); cursor: pointer; padding: 0; font-size: inherit; }
  .ok-line { margin: 0 0 8px; color: var(--ok); }
  h3 { font-size: 13px; margin: 18px 0 2px; }
  .sched td { padding: 6px 8px 6px 0; vertical-align: top; }
  .out { padding: 10px; border-radius: 6px; background: var(--bg); border: 1px solid var(--border); font-size: 12px; }
  .versions { margin-top: 16px; }

  @media (max-width: 1000px) {
    .editor-layout { grid-template-columns: 1fr; }
    .code { height: 420px; }
  }
</style>
