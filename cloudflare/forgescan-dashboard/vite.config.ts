import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: true,
    chunkSizeWarningLimit: 600,
    rollupOptions: {
      output: {
        // Conservative manualChunks. We DELIBERATELY do not split the
        // recharts tree (recharts + react-smooth + d3-* + victory-vendor)
        // — fragmenting that graph triggers TDZ errors at runtime
        // ("Cannot access 'P' before initialization" inside Layer.js)
        // because react-smooth's CommonJS modules contain circular imports
        // that Rollup can only resolve safely when they live in a single
        // automatically-derived chunk. Rollup will still hoist recharts
        // into a shared chunk since multiple pages import it.
        manualChunks(id) {
          if (!id.includes('node_modules')) return undefined;

          // Radix primitives — leaf libs, safe to split.
          if (id.includes('/@radix-ui/')) return 'radix';

          // Lucide icons — leaf lib, safe to split.
          if (id.includes('/lucide-react/')) return 'icons';

          // React + router get the conventional vendor chunk.
          if (
            id.includes('/react/') ||
            id.includes('/react-dom/') ||
            id.includes('/react-router') ||
            id.includes('/scheduler/')
          ) {
            return 'vendor';
          }

          // Everything else (recharts tree, date-fns, etc.) — let Rollup
          // decide. It will create shared chunks for modules imported by
          // multiple pages and inline single-page deps where appropriate.
          return undefined;
        },
      },
    },
  },
  server: {
    port: 3000,
    proxy: {
      '/api': {
        target: 'http://localhost:8787',
        changeOrigin: true,
      },
    },
  },
});
