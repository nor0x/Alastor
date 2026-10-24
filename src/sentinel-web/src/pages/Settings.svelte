<script lang="ts">
  import { canWrite } from '../lib/session.svelte';
  import Groups from './settings/Groups.svelte';
  import Enrollment from './settings/Enrollment.svelte';
  import ApiKeys from './settings/ApiKeys.svelte';
  import Account from './settings/Account.svelte';
  import Audit from './settings/Audit.svelte';
  import Server from './settings/Server.svelte';

  let { section }: { section: string } = $props();

  const sections = [
    { id: 'groups', label: 'Groups', admin: false },
    { id: 'enrollment', label: 'Enrollment', admin: true },
    { id: 'api-keys', label: 'API keys', admin: true },
    { id: 'server', label: 'Server', admin: true },
    { id: 'account', label: 'Account', admin: true },
    { id: 'audit', label: 'Audit log', admin: true },
  ];
  const visible = $derived(sections.filter((s) => !s.admin || canWrite()));
  const current = $derived(visible.some((s) => s.id === section) ? section : 'groups');
</script>

<div class="page-head">
  <div>
    <h1>Settings</h1>
    <p class="sub">Groups, enrolling new servers, API access and the audit trail.</p>
  </div>
</div>

<div class="layout">
  <nav class="side" aria-label="Settings sections">
    {#each visible as s (s.id)}
      <a href="/settings/{s.id}" class:on={current === s.id} aria-current={current === s.id ? 'page' : undefined}>{s.label}</a>
    {/each}
  </nav>
  <div class="content">
    {#if current === 'groups'}<Groups />
    {:else if current === 'enrollment'}<Enrollment />
    {:else if current === 'api-keys'}<ApiKeys />
    {:else if current === 'server'}<Server />
    {:else if current === 'account'}<Account />
    {:else if current === 'audit'}<Audit />{/if}
  </div>
</div>

<style>
  .layout { display: grid; grid-template-columns: 180px minmax(0, 1fr); gap: 24px; align-items: start; }
  .side { display: flex; flex-direction: column; gap: 2px; position: sticky; top: 70px; }
  .side a { padding: 6px 12px; border-radius: var(--radius); color: var(--text); }
  .side a:hover { background: var(--surface-2); text-decoration: none; }
  .side a.on { background: var(--surface-2); color: var(--text-strong); font-weight: 600; box-shadow: inset 2px 0 0 #f78166; }
  @media (max-width: 760px) {
    .layout { grid-template-columns: 1fr; }
    .side { position: static; flex-direction: row; overflow-x: auto; border-bottom: 1px solid var(--border); padding-bottom: 8px; }
    .side a { white-space: nowrap; }
  }
</style>
