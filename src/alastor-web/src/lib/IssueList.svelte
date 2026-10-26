<script lang="ts">
  import { api, errorText, type Issue } from './api';
  import { canWrite } from './session.svelte';
  import { toast } from './toast.svelte';
  import Modal from './ui/Modal.svelte';
  import Severity from './ui/Severity.svelte';
  import Time from './ui/Time.svelte';

  // Open problems, most severe first. Each links to the host tab that explains and fixes it; operators can
  // acknowledge an issue (with a note) so it stops counting in the badge until it resolves or comes back.
  let { issues, showHost = true, compact = false, onchange }: {
    issues: Issue[];
    showHost?: boolean;
    compact?: boolean;
    /** Called after an acknowledge or un-acknowledge succeeds. */
    onchange?: () => void;
  } = $props();

  let acking = $state<Issue | null>(null);
  let ackOpen = $state(false);
  let note = $state('');
  let busy = $state(false);

  function startAck(i: Issue) {
    acking = i;
    note = '';
    ackOpen = true;
  }

  async function submitAck(e: SubmitEvent) {
    e.preventDefault();
    if (!acking) return;
    busy = true;
    try {
      await api(`/api/issues/${acking.id}/ack`, { method: 'POST', body: JSON.stringify({ note: note.trim() || null }) });
      ackOpen = false;
      toast('Acknowledged. It stays listed until the condition clears, and comes back if it reopens.');
      onchange?.();
    } catch (err) {
      toast(errorText(err), 'error');
    } finally {
      busy = false;
    }
  }

  async function unack(i: Issue) {
    try {
      await api(`/api/issues/${i.id}/unack`, { method: 'POST' });
      onchange?.();
    } catch (err) {
      toast(errorText(err), 'error');
    }
  }

  const href = (i: Issue) => (i.tab === 'overview' ? `/hosts/${i.hostId}` : `/hosts/${i.hostId}?tab=${i.tab}`);
</script>

<ul class="issues" class:compact>
  {#each issues as i (i.id)}
    <li class:acked={i.acknowledgedAt && !i.resolvedAt} class:resolved={i.resolvedAt}>
      <span class="sevcol"><Severity value={i.severity} /></span>
      <div class="main">
        <a class="title" href={href(i)}>{i.title}</a>
        {#if i.detail && !compact}<p class="detail">{i.detail}</p>{/if}
        <span class="meta">
          {#if showHost}<a href="/hosts/{i.hostId}">{i.hostName}</a>{#if !i.hostOnline}<span class="muted"> (offline)</span>{/if}<span>·</span>{/if}
          {#if i.resolvedAt}<span>resolved <Time iso={i.resolvedAt} /></span>
          {:else}<span>open since <Time iso={i.firstSeenAt} /></span>{/if}
          {#if i.occurrences > 1}<span title="Times this condition has opened">· {i.occurrences}×</span>{/if}
          {#if !compact}<span>· {i.ruleLabel}</span>{/if}
        </span>
        {#if i.acknowledgedAt && !i.resolvedAt}
          <span class="ack">Acknowledged by {i.acknowledgedBy} <Time iso={i.acknowledgedAt} />{#if i.ackNote}: “{i.ackNote}”{/if}</span>
        {/if}
      </div>
      {#if canWrite() && !i.resolvedAt}
        <div class="act">
          {#if i.acknowledgedAt}<button class="btn small ghost" onclick={() => unack(i)}>Unacknowledge</button>
          {:else}<button class="btn small" onclick={() => startAck(i)}>Acknowledge</button>{/if}
        </div>
      {/if}
    </li>
  {/each}
</ul>

<Modal bind:open={ackOpen} title="Acknowledge issue">
  <form id="ack-form" class="form" onsubmit={submitAck}>
    <p><strong>{acking?.title}</strong>{#if showHost && acking} <span class="muted">on {acking.hostName}</span>{/if}</p>
    <label>
      Note <span class="muted small">(optional, shown with the issue and in the audit log)</span>
      <input class="field" bind:value={note} maxlength="512" placeholder="Planned for Thursday's maintenance window" />
    </label>
    <p class="help">Acknowledging doesn't fix anything: the issue stays listed until the condition clears, and opens again, unacknowledged, if it comes back.</p>
  </form>
  {#snippet footer()}
    <button class="btn" type="button" onclick={() => (ackOpen = false)}>Cancel</button>
    <button class="btn primary" form="ack-form" disabled={busy}>{busy ? 'Saving…' : 'Acknowledge'}</button>
  {/snippet}
</Modal>

<style>
  .issues { list-style: none; margin: 0; padding: 0; }
  li { display: grid; grid-template-columns: 96px minmax(0, 1fr) auto; gap: var(--space-sm); align-items: start; padding: var(--space-sm) var(--space-md); border-bottom: var(--rule-hair) solid var(--border); }
  li:last-child { border-bottom: 0; }
  .compact li { padding: var(--space-xs) var(--space-md); }
  li.acked .title, li.resolved .title { color: var(--muted); }
  .sevcol { padding-top: var(--space-3xs); }
  .main { display: flex; flex-direction: column; gap: var(--space-3xs); min-width: 0; }
  .title { color: var(--text-strong); font-family: var(--font-display); font-weight: 500; overflow-wrap: anywhere; }
  .title:hover { color: var(--link); }
  .detail { color: var(--color-ink-2); font-size: var(--text-sm); }
  .meta { display: flex; flex-wrap: wrap; gap: 0 var(--space-2xs); color: var(--muted); font-size: var(--text-sm); }
  .meta a { color: var(--color-ink-2); }
  .ack { color: var(--muted); font-size: var(--text-sm); }
  .act { padding-top: var(--space-3xs); }
  @media (max-width: 640px) {
    li { grid-template-columns: minmax(0, 1fr); gap: var(--space-2xs); }
  }
</style>
