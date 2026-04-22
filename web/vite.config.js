import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/health': 'http://localhost:8080',
      '/users': 'http://localhost:8080',
      '/messages': 'http://localhost:8080'
    }
  }
});
