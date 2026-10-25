import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';

// The build lands in the server's wwwroot, which is embedded into the single-file server binary.
// Vite's content-hashed /assets are served with an immutable cache header (see Program.cs).
export default defineConfig({
  plugins: [svelte()],
  build: {
    outDir: '../Alastor.Server/wwwroot',
    emptyOutDir: true,
  },
  server: {
    host: true,
    allowedHosts: true,
    // `npm run dev` talks to a server started with `dotnet run --project src/Alastor.Server` on :8080.
    proxy: {
      '/api': 'http://localhost:8080',
      '/hubs': { target: 'http://localhost:8080', ws: true },
      '/openapi': 'http://localhost:8080',
    },
  },
});
