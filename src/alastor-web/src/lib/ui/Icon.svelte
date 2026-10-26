<script lang="ts" module>
  // One 16px stroke set for the whole dashboard. Icons sit beside a word; the word carries the meaning.
  const paths = {
    check: 'm3.5 8.5 3 3 6-7',
    alert: 'M8 2.2 14.5 13.5h-13ZM8 6.5v3.2M8 11.4v.1',
    error: 'M8 2a6 6 0 1 0 0 12A6 6 0 0 0 8 2Zm-2.2 3.8 4.4 4.4m0-4.4-4.4 4.4',
    info: 'M8 2a6 6 0 1 0 0 12A6 6 0 0 0 8 2Zm0 5v4m0-6.2v.1',
    menu: 'M2.5 4.5h11M2.5 8h11M2.5 11.5h11',
    close: 'm4 4 8 8m0-8-8 8',
    external: 'M9.5 2.5h4v4m0-4L8 8m-1.5-4.5h-4v10h10v-4',
    search: 'M7 2.5a4.5 4.5 0 1 0 0 9 4.5 4.5 0 0 0 0-9Zm3.2 7.7 3.3 3.3',
    signout: 'M6.5 2.5h-4v11h4m3-8 3 2.5-3 2.5m3-2.5H6',
  } as const;
  export type IconName = keyof typeof paths;
</script>

<script lang="ts">
  let { name, size = 16, label }: { name: IconName; size?: number; label?: string } = $props();
</script>

<svg class="icon" viewBox="0 0 16 16" width={size} height={size} fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"
  role={label ? 'img' : undefined} aria-label={label} aria-hidden={label ? undefined : 'true'}>
  <path d={paths[name]} />
</svg>

<style>
  .icon { flex: none; display: inline-block; vertical-align: -0.15em; }
</style>
