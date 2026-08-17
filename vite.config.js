import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import { fileURLToPath } from 'node:url'

export default defineConfig({
  plugins: [vue()],
  resolve: {
    alias: {
      // sm-crypto 的 rng.js 里有防御性 require('crypto'),浏览器打包时指向 globalThis.crypto
      crypto: fileURLToPath(new URL('./web/shims/node-crypto-stub.js', import.meta.url)),
    },
  },
  build: {
    outDir: 'dist',
    target: 'es2022',
  },
})
