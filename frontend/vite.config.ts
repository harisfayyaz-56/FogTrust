import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    host: '127.0.0.1',
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8000',
        // Keep the browser's Host header so Django's CSRF Origin check sees
        // http://127.0.0.1:5173 on both sides. changeOrigin:true would rewrite
        // Host to :8000 while Origin stays :5173 and every POST would 403.
        changeOrigin: false,
        secure: false,
      },
    },
  },
});

