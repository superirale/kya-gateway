import { defineConfig } from 'vite';
import preact from '@preact/preset-vite';
import { fileURLToPath } from 'node:url';

const KYA = process.env.KYA_URL ?? 'http://localhost:8080';
const MERCHANT = process.env.MERCHANT_URL ?? 'http://localhost:8081';

// The browser only talks to same-origin /kya (public + consumer routes) and
// /merchant (the merchant agent, which holds the merchant API key server-side).
const proxy = {
  '/kya': { target: KYA, changeOrigin: true, rewrite: (p: string) => p.replace(/^\/kya/, '') },
  '/merchant': { target: MERCHANT, changeOrigin: true, rewrite: (p: string) => p.replace(/^\/merchant/, '') },
};

export default defineConfig({
  plugins: [preact()],
  resolve: {
    alias: { '@kya/sdk': fileURLToPath(new URL('../../sdk/typescript/src/index.ts', import.meta.url)) },
  },
  server: { port: 5173, proxy },
  preview: { port: 4173, proxy },
});
