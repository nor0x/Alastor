// Temporary: a dev server on :5180 against a throwaway backend on :8090, for checking the hosts grid. Delete after use.
import { svelte } from '@sveltejs/vite-plugin-svelte';

export default {
  plugins: [svelte()],
  server: {
    port: 5180,
    strictPort: true,
    proxy: {
      '/api': 'http://localhost:8090',
      '/hubs': { target: 'http://localhost:8090', ws: true },
    },
  },
};
