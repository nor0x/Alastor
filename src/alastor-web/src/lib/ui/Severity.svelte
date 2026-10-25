<script lang="ts">
  import type { Severity } from '../api';
  let { value }: { value: Severity } = $props();
</script>

<span class="sev sev-{value.toLowerCase()}">{value}</span>
