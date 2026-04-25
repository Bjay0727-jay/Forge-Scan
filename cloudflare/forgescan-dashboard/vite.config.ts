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
        manualChunks(id) {
          if (!id.includes('node_modules')) return undefined;

          // Heavy chart engine — only loaded by pages that render charts.
          if (id.includes('/recharts/') || id.includes('/d3-')) return 'charts';

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
