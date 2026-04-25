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
  // Pre-bundle the recharts tree as ESM. react-smooth ships CommonJS that
  // does `require('react')` inside Animate.js — without this Vite can split
  // react-smooth into a chunk where the React import resolves to `undefined`
  // at runtime, producing
  //   "Cannot read properties of undefined (reading 'PureComponent')".
  optimizeDeps: {
    include: ['recharts', 'react-smooth', 'react-is', 'prop-types'],
  },
  build: {
    outDir: 'dist',
    sourcemap: true,
    chunkSizeWarningLimit: 600,
    // Transform mixed-ESM CommonJS modules so react-smooth's `require('react')`
    // resolves through the same interop wrapper as our ESM imports.
    commonjsOptions: {
      transformMixedEsModules: true,
    },
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (!id.includes('node_modules')) return undefined;

          // Charts: keep recharts + ALL of its transitive React consumers
          // (react-smooth, victory-vendor, d3-*, decimal.js-light, etc.)
          // in one chunk so the CJS-to-ESM interop is consistent.
          if (
            id.includes('/recharts/') ||
            id.includes('/react-smooth/') ||
            id.includes('/victory-vendor/') ||
            id.includes('/d3-') ||
            id.includes('/decimal.js-light/') ||
            id.includes('/internmap/')
          ) {
            return 'charts';
          }

          // Radix primitives bundle on their own — used by the UI kit.
          if (id.includes('/@radix-ui/')) return 'radix';

          // Icon set ships hundreds of icons; keep separate.
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

          return 'libs';
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
