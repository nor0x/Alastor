<script lang="ts">
  import { canWrite } from '../lib/session.svelte';
  import Groups from './settings/Groups.svelte';
  import Enrollment from './settings/Enrollment.svelte';
  import ApiKeys from './settings/ApiKeys.svelte';
  import Account from './settings/Account.svelte';
  import Audit from './settings/Audit.svelte';
  import Server from './settings/Server.svelte';
  import Notifications from './settings/Notifications.svelte';
  import Security from './settings/Security.svelte';
  import Data from './settings/Data.svelte';
  import ServerLog from './settings/ServerLog.svelte';

  let { section }: { section: string } = $props();

  const sections = [
    { id: 'groups', label: 'Groups', admin: false },
    { id: 'enrollment', label: 'Enrollment', admin: true },
    { id: 'notifications', label: 'Notifications', admin: true },
    { id: 'api-keys', label: 'API keys', admin: true },
    { id: 'security', label: 'Security', admin: true },
    { id: 'server', label: 'Server', admin: true },
    { id: 'data', label: 'Alastor data', admin: true },
    { id: 'server-log', label: 'Server log', admin: true },
    { id: 'account', label: 'Account', admin: true },
    { id: 'audit', label: 'Audit log', admin: true },
  ];
  const visible = $derived(sections.filter((s) => !s.admin || canWrite()));
  const current = $derived(visible.some((s) => s.id === section) ? section : 'groups');
</script>

<div class="page-head">
  <div>
    <h1>Settings</h1>
    <p class="sub">Groups, enrolling new servers, alert notifications, API access, this server's own security, data and log, and the audit trail.</p>
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
    {:else if current === 'notifications'}<Notifications />
    {:else if current === 'api-keys'}<ApiKeys />
    {:else if current === 'security'}<Security />
    {:else if current === 'server'}<Server />
    {:else if current === 'data'}<Data />
    {:else if current === 'server-log'}<ServerLog />
    {:else if current === 'account'}<Account />
    {:else if current === 'audit'}<Audit />{/if}
  </div>
</div>

<style>
  .layout { display: grid; grid-template-columns: 184px minmax(0, 1fr); gap: var(--space-lg); align-items: start; }
  .side { display: flex; flex-direction: column; gap: var(--space-3xs); position: sticky; top: var(--space-lg); padding-right: var(--space-md); box-shadow: inset -1px 0 0 var(--border); }
  .side a { display: flex; align-items: center; min-height: 36px; padding: 0 var(--space-sm); border-radius: var(--radius-input); color: var(--color-ink-2); font-family: var(--font-display); font-weight: 500; white-space: nowrap; }
  .side a:hover { background: var(--color-paper-2); color: var(--text-strong); text-decoration: none; }
  .side a:active { background: var(--color-paper-3); }
  .side a:focus-visible { outline-offset: -2px; }
  .side a.on { background: var(--color-accent-wash); color: var(--color-accent-deep); }
  @media (max-width: 760px) {
    .layout { grid-template-columns: minmax(0, 1fr); }
    .side { position: static; flex-direction: row; overflow-x: auto; padding: 0 0 var(--space-xs); box-shadow: inset 0 -1px 0 var(--border); }
  }
</style>
