<script lang="ts">
  import { api, errorText, type Group } from '../../lib/api';
  import { fleet, refreshFleet } from '../../lib/fleet.svelte';
  import { canWrite } from '../../lib/session.svelte';
  import { toast } from '../../lib/toast.svelte';
  import { confirm } from '../../lib/ui/confirm.svelte';
  import Icon from '../../lib/ui/Icon.svelte';
  import Modal from '../../lib/ui/Modal.svelte';

  let open = $state(false);
  let editing = $state<Group | null>(null);
  let name = $state('');
  let description = $state('');
  let busy = $state(false);
  let error = $state('');

  $effect(() => {
    refreshFleet();
  });

  function edit(g: Group | null) {
    editing = g;
    name = g?.name ?? '';
    description = g?.description ?? '';
    error = '';
    open = true;
  }

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    busy = true;
    error = '';
    try {
      const body = JSON.stringify({ name: name.trim(), description: description.trim() || null });
      if (editing) await api(`/api/groups/${editing.id}`, { method: 'PUT', body });
      else await api('/api/groups', { method: 'POST', body });
      toast(editing ? 'Group updated.' : `Group "${name.trim()}" created.`);
      open = false;
      refreshFleet();
    } catch (err) {
      error = errorText(err);
    } finally {
      busy = false;
    }
  }

  async function remove(g: Group) {
    const ok = await confirm(`Delete group "${g.name}"?`, `${g.hostCount} host${g.hostCount === 1 ? '' : 's'} will have no group, and the group's policy overrides are deleted. Those hosts fall back to the global policy.`, { confirmLabel: 'Delete group', danger: true });
    if (!ok) return;
    try {
      await api(`/api/groups/${g.id}`, { method: 'DELETE' });
      toast(`Group "${g.name}" deleted.`);
      refreshFleet();
    } catch (e) {
      toast(errorText(e), 'error');
    }
  }
</script>

<section class="card">
  <header>
    <h2>Groups</h2>
    {#if canWrite()}<button class="btn small" onclick={() => edit(null)}>+ New group</button>{/if}
  </header>
  <p class="muted small intro">A host belongs to at most one group. Each group can override the global policy, for example stricter banning on public web servers.</p>
  {#if fleet.groups.length}
    <div class="table-wrap">
    <table class="table">
      <thead><tr><th>Name</th><th class="num">Hosts</th><th>Policy</th>{#if canWrite()}<th></th>{/if}</tr></thead>
      <tbody>
        {#each fleet.groups as g (g.id)}
          <tr>
            <td><strong class="gname">{g.name}</strong>{#if g.description}<div class="muted small">{g.description}</div>{/if}</td>
            <td class="num"><a href="/hosts?group={g.id}">{g.hostCount}</a></td>
            <td><a class="nowrap" href="/policies/group/{g.id}">overrides</a></td>
            {#if canWrite()}
              <td class="actions">
                <button class="btn small" onclick={() => edit(g)}>Edit</button>
                <button class="btn small danger" onclick={() => remove(g)}>Delete</button>
              </td>
            {/if}
          </tr>
        {/each}
      </tbody>
    </table>
    </div>
  {:else}
    <div class="empty">No groups yet.</div>
  {/if}
</section>

<Modal bind:open title={editing ? `Edit ${editing.name}` : 'New group'}>
  <form id="group-form" class="form" onsubmit={submit}>
    <label>Name <input class="field" bind:value={name} maxlength="64" required placeholder="web-servers" /></label>
    <label>Description <input class="field" bind:value={description} maxlength="200" placeholder="Public nginx boxes" /></label>
    {#if error}<div class="banner bad" role="alert"><Icon name="error" /><p>{error}</p></div>{/if}
  </form>
  {#snippet footer()}
    <button class="btn" onclick={() => (open = false)}>Cancel</button>
    <button class="btn primary" form="group-form" disabled={busy}>{editing ? 'Save' : 'Create'}</button>
  {/snippet}
</Modal>

<style>
  .intro { margin: 0; padding: var(--space-sm) var(--space-md); max-width: 75ch; border-bottom: var(--rule-hair) solid var(--border); }
  .gname { font-family: var(--font-display); font-weight: 600; color: var(--text-strong); }
  .num a { font-family: var(--font-display); font-weight: 600; font-variant-numeric: tabular-nums; }
  .num a:focus-visible { outline: 2px solid var(--focus); outline-offset: 2px; }
  .num a:active { color: var(--color-accent-deep); }
  .banner > :global(.icon) { margin-top: var(--space-3xs); color: var(--bad); }
</style>
