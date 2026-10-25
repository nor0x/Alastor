<script lang="ts">
  import { api, errorText } from './api';
  import { fleet } from './fleet.svelte';
  import { toast } from './toast.svelte';
  import Modal from './ui/Modal.svelte';

  // Manual ban of an IP or CIDR on all hosts or a chosen subset. The server refuses targets that cover your
  // own address, overlap the allowlist, or are wider than /8 (IPv4) or /32 (IPv6), and says why.
  let { open = $bindable(false), hostIds = [], target: initialTarget = '' }: { open?: boolean; hostIds?: string[]; target?: string } = $props();

  let target = $state('');
  let reason = $state('');
  let everywhere = $state(true);
  let selected = $state<string[]>([]);
  let busy = $state(false);
  let error = $state('');

  $effect(() => {
    if (open) {
      target = initialTarget;
      reason = '';
      error = '';
      everywhere = hostIds.length === 0;
      selected = [...hostIds];
    }
  });

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    if (!everywhere && selected.length === 0) {
      error = 'Pick at least one host.';
      return;
    }
    busy = true;
    error = '';
    try {
      const res = await api<{ target: string; commands: unknown[] }>('/api/bans', {
        method: 'POST',
        body: JSON.stringify({ target: target.trim(), hostIds: everywhere ? null : selected, reason: reason.trim() || null }),
      });
      toast(`Ban for ${res.target} sent to ${res.commands.length} host${res.commands.length === 1 ? '' : 's'}. It shows up once the agents confirm.`);
      open = false;
    } catch (err) {
      error = errorText(err);
    } finally {
      busy = false;
    }
  }
</script>

<Modal bind:open title="Ban an IP or network">
  <form id="ban-form" class="form" onsubmit={submit}>
    <label>
      IP address or CIDR
      <input class="field mono" bind:value={target} placeholder="203.0.113.7 or 198.51.100.0/24" required autocomplete="off" />
    </label>
    <label>
      Reason <span class="muted small">(optional, shown in the audit log)</span>
      <input class="field" bind:value={reason} maxlength="200" placeholder="Credential stuffing against nginx" />
    </label>
    <fieldset>
      <legend class="lbl">Where</legend>
      <label class="check"><input type="radio" bind:group={everywhere} value={true} /> All hosts ({fleet.hosts.length})</label>
      <label class="check"><input type="radio" bind:group={everywhere} value={false} /> Selected hosts</label>
      {#if !everywhere}
        <div class="hosts">
          {#each fleet.hosts as h (h.id)}
            <label class="check"><input type="checkbox" bind:group={selected} value={h.id} /> {h.name} {#if !h.isOnline}<span class="muted small">(offline, applies when it returns)</span>{/if}</label>
          {/each}
        </div>
      {/if}
    </fieldset>
    <p class="help">Manual bans go into fail2ban's <code>alastor-manual</code> jail (or become a CrowdSec decision on hosts with <code>banning.engine: crowdsec</code>) and last until you unban, unless the policy sets <code>banning.manualBantime</code>. CrowdSec has no permanent bans, so there "permanent" means ten years.</p>
    {#if error}<div class="banner bad" role="alert"><p>{error}</p></div>{/if}
  </form>
  {#snippet footer()}
    <button class="btn" type="button" onclick={() => (open = false)}>Cancel</button>
    <button class="btn solid-danger" form="ban-form" disabled={busy}>{busy ? 'Sending…' : 'Ban'}</button>
  {/snippet}
</Modal>

<style>
  fieldset { border: 0; padding: 0; margin: 0; display: flex; flex-direction: column; gap: 8px; }
  .hosts { display: flex; flex-direction: column; gap: 6px; max-height: 200px; overflow: auto; padding: 8px 12px; border: 1px solid var(--border); border-radius: var(--radius); }
</style>
