<script lang="ts">
  import type { Severity } from '../api';
  let { value, title }: { value: Severity; title?: string } = $props();
</script>

<span class="sev sev-{value.toLowerCase()}" {title}>{value}</span>
